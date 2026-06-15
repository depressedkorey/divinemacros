from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from flask import Blueprint, Response, current_app, jsonify, make_response, redirect, request, send_file, stream_with_context
from sqlalchemy import or_

from auth.session import get_session_manager
from database import db
from models import ClientFeatureLock, ClientNotification, CommunityChatMessage, CommunityProfile, License, Product, UserEntitlement
from utils.audit import audit_event
from utils.crypto import sha256_hex
from utils.rate_limiter import get_limiter
from utils.discord_roles import grant_customer_role, revoke_customer_role, grant_standalone_role

web_bp = Blueprint('web_compat', __name__)

_dashboard_sessions: dict[str, dict] = {}
_dashboard_resets: dict[str, float] = {}
_pending_auth_tokens: dict[str, dict] = {}
_release_cache: dict[str, dict[str, object | None]] = {
    'normal': {'ts_ms': 0, 'data': None},
    'direct_exe': {'ts_ms': 0, 'data': None},
}
# Cache: filename -> (asset_id, fetched_at_ms)
_asset_id_cache: dict[str, tuple[int, int]] = {}
_state_lock = Lock()
_community_store_lock = Lock()
_DASHBOARD_SESSION_MAX_TTL_MS = 24 * 60 * 60 * 1000
_PENDING_AUTH_TTL_MS = 3 * 60 * 1000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _unix_ms() -> int:
    return int(time.time() * 1000)


def _client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _website_root() -> Path:
    # Support both local repo layout (.../backend/web/routes.py -> repo/website)
    # and container layout (/app/web/routes.py -> /app/website).
    explicit = str(current_app.config.get('WEBSITE_ROOT', '')).strip()
    if explicit:
        root = Path(explicit)
        if root.exists():
            return root

    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / 'website' / 'public',
        here.parents[1] / 'website' / 'public',
        Path('/app/website/public'),
        here.parents[2] / 'website',
        here.parents[1] / 'website',
        Path('/app/website'),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _safe_web_path(path_text: str) -> Path | None:
    root = _website_root().resolve()
    target = (root / path_text).resolve()
    if not str(target).startswith(str(root)):
        return None
    return target


def _cleanup_state() -> None:
    now = _unix_ms()
    with _state_lock:
        dead_sessions = [sid for sid, row in _dashboard_sessions.items() if int(row.get('expires_at_ms', 0)) <= now]
        for sid in dead_sessions:
            _dashboard_sessions.pop(sid, None)

        dead_pending = [t for t, row in _pending_auth_tokens.items() if int(row.get('exp', 0)) <= now]
        for t in dead_pending:
            _pending_auth_tokens.pop(t, None)

        cooldown_window = 24 * 60 * 60 * 1000
        dead_resets = [rid for rid, ts in _dashboard_resets.items() if int(ts) + cooldown_window <= now]
        for rid in dead_resets:
            _dashboard_resets.pop(rid, None)


def _session_secret() -> str:
    return str(current_app.config.get('DASHBOARD_SESSION_SECRET') or current_app.config.get('SECRET_KEY') or '')


def _session_sig(payload: str) -> str:
    secret = _session_secret()
    return hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()


def _build_session_token(session_id: str, session_row: dict | None = None) -> str:
    if session_row:
        payload_obj = {
            'sid': str(session_id or ''),
            'exp': int(session_row.get('expires_at_ms', 0)),
            'user': session_row.get('user') or {},
            'v': 2,
        }
        packed = json.dumps(payload_obj, separators=(',', ':'), ensure_ascii=False)
        payload = base64.urlsafe_b64encode(packed.encode('utf-8')).decode('ascii').rstrip('=')
    else:
        payload = str(session_id or '')
    return f'{payload}.{_session_sig(payload)}'


def _verify_session_token(token: str) -> str | None:
    raw = str(token or '')
    if '.' not in raw:
        return None
    payload, sig = raw.rsplit('.', 1)
    expected = _session_sig(payload)
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


def _pack_signed_json(payload_obj: dict) -> str:
    packed = json.dumps(payload_obj, separators=(',', ':'), ensure_ascii=False)
    payload = base64.urlsafe_b64encode(packed.encode('utf-8')).decode('ascii').rstrip('=')
    return f'{payload}.{_session_sig(payload)}'


def _unpack_signed_json(token: str) -> dict | None:
    payload = _verify_session_token(token)
    if not payload:
        return None
    try:
        padded = payload + ('=' * ((4 - len(payload) % 4) % 4))
        unpacked = base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8')
        data = json.loads(unpacked)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _decode_session_payload(token: str) -> dict | None:
    payload = _verify_session_token(token)
    if not payload:
        return None
    try:
        padded = payload + ('=' * ((4 - len(payload) % 4) % 4))
        unpacked = base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8')
        data = json.loads(unpacked)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if int(data.get('v', 0)) != 2:
        return None
    exp = int(data.get('exp', 0))
    user = data.get('user') or {}
    if exp <= 0 or not isinstance(user, dict):
        return None
    return {
        'sid': str(data.get('sid') or ''),
        'expires_at_ms': exp,
        'user': user,
    }


def _set_dashboard_cookie(response, token: str) -> None:
    ttl_ms = min(int(current_app.config.get('DASHBOARD_SESSION_TTL_MS', _DASHBOARD_SESSION_MAX_TTL_MS)), _DASHBOARD_SESSION_MAX_TTL_MS)
    # Always Secure in production â€” ProxyFix handles X-Forwarded-Proto,
    # but some proxies strip it; force True when SITE_URL is https.
    site_url = str(current_app.config.get('SITE_URL', ''))
    secure_cookie = request.is_secure or site_url.startswith('https')
    response.set_cookie(
        str(current_app.config.get('DASHBOARD_COOKIE_NAME', 'zenith_dash')),
        token,
        max_age=max(60, ttl_ms // 1000),
        httponly=True,
        secure=secure_cookie,
        samesite='Lax',
        path='/',
    )


def _clear_dashboard_cookie(response) -> None:
    site_url = str(current_app.config.get('SITE_URL', ''))
    secure_cookie = request.is_secure or site_url.startswith('https')
    response.set_cookie(
        str(current_app.config.get('DASHBOARD_COOKIE_NAME', 'zenith_dash')),
        '',
        max_age=0,
        httponly=True,
        secure=secure_cookie,
        samesite='Lax',
        path='/',
    )


def _dashboard_session() -> tuple[str, dict] | tuple[None, None]:
    _cleanup_state()
    cookie_name = str(current_app.config.get('DASHBOARD_COOKIE_NAME', 'zenith_dash'))
    raw = request.cookies.get(cookie_name, '')

    # Fallback: Authorization: Bearer <signed-token> (localStorage-based auth).
    # Cloudflare can strip Set-Cookie from responses, so the frontend stores
    # the token in localStorage and sends it as a Bearer header instead.
    if not raw:
        auth_hdr = request.headers.get('Authorization', '')
        if auth_hdr.startswith('Bearer '):
            raw = auth_hdr[7:].strip()

    now = _unix_ms()

    decoded = _decode_session_payload(raw)
    if decoded:
        if int(decoded.get('expires_at_ms', 0)) <= now:
            return None, None
        sid = str(decoded.get('sid') or '')
        row = {
            'expires_at_ms': int(decoded.get('expires_at_ms', 0)),
            'user': decoded.get('user') or {},
        }
        return sid, row

    return None, None


def _dashboard_user_or_401():
    session_id, row = _dashboard_session()
    if not session_id or not row:
        return None, (jsonify({'ok': False, 'error': 'Not authenticated'}), 401)
    return row.get('user') or {}, None


def _safe_next_path(raw: str) -> str:
    text = str(raw or '').strip()
    if not text:
        return '/dashboard?auth=ok'
    if not text.startswith('/') or text.startswith('//'):
        return '/dashboard?auth=ok'
    lowered = text.lower()
    if lowered.startswith('/auth/discord') or lowered.startswith('/api/auth/discord'):
        return '/dashboard?auth=ok'
    return text[:300]


def _site_redirect_url(next_path: str) -> str:
    safe_path = _safe_next_path(next_path)
    site_url = str(current_app.config.get('SITE_URL', '')).strip().rstrip('/')
    if site_url:
        return f'{site_url}{safe_path}'
    return safe_path


def _site_redirect_with_token(next_path: str, token: str, *, auth_ok: bool = False) -> str:
    target = _site_redirect_url(next_path)
    if auth_ok:
        sep = '&' if '?' in target else '?'
        target = f'{target}{sep}auth=ok'
    return f'{target}#zdash_tok={quote(str(token or ""), safe="")}'


def _build_oauth_state(next_path: str) -> str:
    # [SECURITY HARDENING] Stateless signed OAuth state avoids in-memory
    # callback mismatches across workers while preserving CSRF integrity.
    payload = {
        'v': 1,
        'n': secrets.token_hex(12),
        'next': _safe_next_path(next_path),
        'exp': _unix_ms() + (10 * 60 * 1000),
    }
    return _pack_signed_json(payload)


def _read_oauth_state(raw_state: str) -> dict | None:
    payload = _unpack_signed_json(raw_state)
    if not payload:
        return None
    if int(payload.get('v', 0)) != 1:
        return None
    exp = int(payload.get('exp', 0))
    if exp <= _unix_ms():
        return None
    nonce = str(payload.get('n') or '').strip()
    if len(nonce) < 8:
        return None
    return {'next': _safe_next_path(payload.get('next', '/dashboard?auth=ok'))}


def _discord_oauth_ready() -> bool:
    return bool(
        str(current_app.config.get('DISCORD_OAUTH_CLIENT_ID', '')).strip()
        and str(current_app.config.get('DISCORD_OAUTH_CLIENT_SECRET', '')).strip()
        and _session_secret()
    )


def _json_from_url(req: Request) -> dict:
    with urlopen(req, timeout=12) as resp:  # nosec B310: fixed allow-listed HTTPS endpoint.
        body = resp.read().decode('utf-8', errors='replace')
    return json.loads(body or '{}')


_DISCORD_UA = 'Mozilla/5.0 (compatible; Divine Macros/1.2; +https://divinemacros.store)'


def _exchange_discord_code(code: str) -> dict | None:
    body = urlencode({
        'client_id': str(current_app.config.get('DISCORD_OAUTH_CLIENT_ID', '')).strip(),
        'client_secret': str(current_app.config.get('DISCORD_OAUTH_CLIENT_SECRET', '')).strip(),
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': str(current_app.config.get('DISCORD_OAUTH_REDIRECT_URI', '')).strip(),
    }).encode('utf-8')
    req = Request(
        'https://discord.com/api/oauth2/token',
        data=body,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': _DISCORD_UA,
        },
        method='POST',
    )
    try:
        return _json_from_url(req)
    except HTTPError as exc:
        try:
            payload = (exc.read() or b'').decode('utf-8', errors='replace')
            data = json.loads(payload or '{}')
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {'error': f'http_{int(exc.code)}'}
    except Exception as exc:
        try:
            audit_event('web.oauth.token.exception', ip=_client_ip(), error=str(exc)[:180])
        except Exception:
            pass
        return {
            'error': 'exception',
            'error_description': str(exc)[:180],
        }


def _fetch_discord_user(access_token: str) -> dict | None:
    req = Request(
        'https://discord.com/api/users/@me',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'User-Agent': _DISCORD_UA,
        },
        method='GET',
    )
    try:
        return _json_from_url(req)
    except Exception:
        return None


def _mask_key(license_key: str) -> str:
    text = str(license_key or '').strip()
    if len(text) <= 8:
        return text
    return f'{text[:4]}-****-****-{text[-4:]}'


def _is_expired(item: License) -> bool:
    if item.expires_at is None:
        return False
    exp = item.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return _utc_now() > exp


def _license_status(item: License) -> str:
    if bool(item.is_revoked):
        return 'inactive'
    if _is_expired(item):
        return 'expired'
    if item.hwid_hash:
        return 'used'
    return 'active'


def _license_plan(item: License) -> str:
    tier = str(item.tier or 'monthly').strip().lower()
    if tier in {'lifetime', 'lifetime_pro', 'pro_lifetime', 'permanent', 'forever'}:
        return 'pro_lifetime'
    if tier in {'lifetime_core', 'core_lifetime'}:
        return 'core_lifetime'
    if tier in {'3month', 'pro', 'pro_monthly'}:
        return 'pro_monthly'
    return 'core_monthly'


def _normalize_checkout_plan(raw_plan: str) -> str:
    text = str(raw_plan or '').strip().lower()
    if text in {'lifetime', 'lifetime_pro', 'pro_lifetime'}:
        return 'pro_lifetime'
    if text in {'lifetime_core', 'core_lifetime'}:
        return 'core_lifetime'
    if text in {'3month', 'pro', 'pro_monthly'}:
        return 'pro_monthly'
    return 'core_monthly'


def _plan_display_name(plan: str) -> str:
    normalized = _normalize_checkout_plan(plan)
    return {
        'core_monthly': 'Core Monthly',
        'core_lifetime': 'Core Lifetime',
        'pro_monthly': 'Pro Monthly',
        'pro_lifetime': 'Pro Lifetime',
    }[normalized]


def _plan_is_pro(plan: str) -> bool:
    return _normalize_checkout_plan(plan) in {'pro_monthly', 'pro_lifetime'}


def _license_role(item: License) -> str:
    meta = item.extra_metadata or {}
    role = str(meta.get('access_role') or meta.get('role') or 'customer').strip().lower()
    return role if role in {'customer', 'moderator', 'admin'} else 'customer'


def _license_expires_iso(item: License) -> str | None:
    if item.expires_at is None:
        return None
    exp = item.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp.isoformat()


def _license_created_iso(item: License) -> str | None:
    if item.created_at is None:
        return None
    dt = item.created_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _licenses_for_user(user: dict) -> list[License]:
    uid = str(user.get('id') or '').strip()
    email = str(user.get('email') or '').strip().lower()
    if not uid and not email:
        return []

    rows = License.query.order_by(License.id.desc()).limit(5000).all()
    matched: list[License] = []
    for item in rows:
        meta = item.extra_metadata or {}
        linked_id = str(meta.get('discord_id') or meta.get('discordId') or '').strip()
        linked_email = str(meta.get('email') or '').strip().lower()
        if uid and linked_id and linked_id == uid:
            matched.append(item)
            continue
        if email and linked_email and linked_email == email:
            matched.append(item)
            continue
    return matched


def _choose_summary_license(rows: list[License]) -> License | None:
    active = [row for row in rows if (not row.is_revoked) and (not _is_expired(row))]
    return active[0] if active else (rows[0] if rows else None)


def _release_repo() -> str:
    raw = str(current_app.config.get('GITHUB_RELEASE_REPO', '')).strip()
    if not raw:
        return ''
    text = raw.replace('\\', '/').strip().strip('/')
    lowered = text.lower()

    if lowered.startswith('https://github.com/') or lowered.startswith('http://github.com/'):
        parts = text.split('/', 3)
        text = parts[3] if len(parts) >= 4 else ''
    elif lowered.startswith('https://api.github.com/repos/') or lowered.startswith('http://api.github.com/repos/'):
        marker = '/repos/'
        idx = lowered.find(marker)
        text = text[idx + len(marker):] if idx >= 0 else text

    text = text.strip().strip('/')
    if text.lower().endswith('.git'):
        text = text[:-4]
    if text.lower().endswith('/releases'):
        text = text[:-9]
    if text.lower().endswith('/release'):
        text = text[:-8]

    parts = [part for part in text.split('/') if part]
    if len(parts) >= 2:
        return f'{parts[0]}/{parts[1]}'
    return text


def _github_release_ready() -> bool:
    return bool(
        _release_repo()
        and str(current_app.config.get('GITHUB_TOKEN', '')).strip()
    )


def _resolve_standalone_asset_id(download_ref: str) -> tuple[int, str] | tuple[None, None]:
    """
    Given a download_ref URL like:
      https://github.com/owner/repo/releases/download/vX.Y.Z/ZenithStunSlam.exe
    Return (asset_id, filename) by querying the LATEST GitHub release for that filename.
    Always uses the latest release so no version bump is needed in download_refs.
    Results are cached for 5 minutes.
    """
    import re as _re
    m = _re.search(r'/releases/download/[^/]+/([^/?#]+)$', download_ref)
    if not m:
        # Fallback: treat the ref as a bare filename
        filename = download_ref.rsplit('/', 1)[-1]
        if not filename:
            return None, None
    else:
        filename = m.group(1)

    now = _unix_ms()
    cached = _asset_id_cache.get(filename)
    if cached and (now - cached[1]) < 300_000:
        return cached[0], filename

    repo = _release_repo()
    if not repo:
        return None, None
    try:
        # First check the latest release â€” ideal path for the main EXE.
        req = _github_api_request(
            f'https://api.github.com/repos/{repo}/releases/latest'
        )
        payload = _json_from_url(req)
        for asset in payload.get('assets') or []:
            if asset.get('name', '').lower() == filename.lower():
                asset_id = int(asset.get('id') or 0)
                if asset_id:
                    _asset_id_cache[filename] = (asset_id, now)
                    return asset_id, filename

        # Standalone EXEs may live in an older release (not always re-published
        # with every main-app release).  Search the 10 most recent releases so
        # users always get a working download even when the file isn't in the
        # latest release tag.
        req2 = _github_api_request(
            f'https://api.github.com/repos/{repo}/releases?per_page=10'
        )
        releases = _json_from_url(req2)
        for release in (releases or []):
            for asset in release.get('assets') or []:
                if asset.get('name', '').lower() == filename.lower():
                    asset_id = int(asset.get('id') or 0)
                    if asset_id:
                        _asset_id_cache[filename] = (asset_id, now)
                        return asset_id, filename
    except Exception:
        pass
    return None, None


def _release_asset_preferred_name() -> str:
    return str(current_app.config.get('RELEASE_ASSET_NAME', '')).strip().lower()


def _release_exe_asset_preferred_name() -> str:
    return str(
        current_app.config.get('RELEASE_EXE_ASSET_NAME', '')
        or current_app.config.get('RELEASE_DIRECT_EXE_ASSET_NAME', '')
    ).strip().lower()


def _github_api_request(url: str, *, accept: str = 'application/vnd.github+json'):
    token = str(current_app.config.get('GITHUB_TOKEN', '')).strip()
    headers = {
        'Accept': accept,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'divinemacros-release-broker',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return Request(url, headers=headers, method='GET')


def _is_installer_asset_name(name: str) -> bool:
    lowered = str(name or '').strip().lower()
    return (
        lowered.endswith('.msi')
        or 'setup' in lowered
        or 'install' in lowered
        or 'nsis' in lowered
    )


def _is_direct_client_asset_name(name: str) -> bool:
    lowered = str(name or '').strip().lower()
    return lowered.endswith('.exe') and not _is_installer_asset_name(lowered)


def _pick_release_asset(
    assets: list[dict],
    *,
    direct_exe_only: bool = False,
    preferred_name: str = '',
) -> dict | None:
    if not assets:
        return None
    if preferred_name:
        for asset in assets:
            asset_name = str(asset.get('name') or '').strip().lower()
            if asset_name == preferred_name:
                if direct_exe_only and not _is_direct_client_asset_name(asset_name):
                    break
                return asset

    if direct_exe_only:
        for asset in assets:
            name = str(asset.get('name') or '').strip().lower()
            if 'portable' in name and _is_direct_client_asset_name(name):
                return asset

        for asset in assets:
            name = str(asset.get('name') or '').strip().lower()
            if _is_direct_client_asset_name(name):
                return asset
        return None

    # Normal downloads are installers. Direct/portable executables are selected
    # only by the direct_exe_only branch above.
    for asset in assets:
        name = str(asset.get('name') or '').strip().lower()
        if name.endswith('.exe') and _is_installer_asset_name(name):
            return asset

    for asset in assets:
        name = str(asset.get('name') or '').strip().lower()
        if name.endswith('.msi'):
            return asset

    for suffix in ('.zip', '.exe'):
        for asset in assets:
            name = str(asset.get('name') or '').strip().lower()
            if name.endswith(suffix):
                return asset

    return assets[0]


def _release_payload_to_data(payload: dict, asset: dict) -> dict | None:
    data = {
        'version': str(payload.get('tag_name') or payload.get('name') or '').strip(),
        'publishedAt': str(payload.get('published_at') or '').strip(),
        'releaseName': str(payload.get('name') or '').strip(),
        'releaseNotes': str(payload.get('body') or '').strip()[:2000],
        'assetId': int(asset.get('id') or 0),
        'assetName': str(asset.get('name') or '').strip(),
        'assetSize': int(asset.get('size') or 0),
        'browserDownloadUrl': str(asset.get('browser_download_url') or '').strip(),
    }
    if not data['assetId'] or not data['assetName']:
        return None
    return data


def _latest_release_data(*, direct_exe_only: bool = False) -> dict | None:
    if not _github_release_ready():
        return None

    now = _unix_ms()
    cache_key = 'direct_exe' if direct_exe_only else 'normal'
    bucket = _release_cache.get(cache_key) or {'ts_ms': 0, 'data': None}
    cached = bucket.get('data')
    cache_ts = int(bucket.get('ts_ms') or 0)
    if cached and (now - cache_ts) < 30_000:
        return cached  # type: ignore[return-value]

    repo = _release_repo()
    preferred_name = _release_exe_asset_preferred_name() if direct_exe_only else _release_asset_preferred_name()
    data = None
    try:
        req = _github_api_request(f'https://api.github.com/repos/{repo}/releases/latest')
        payload = _json_from_url(req)
    except Exception:
        payload = {}

    assets = payload.get('assets') or []
    if isinstance(assets, list):
        asset = _pick_release_asset(
            assets,
            direct_exe_only=direct_exe_only,
            preferred_name=preferred_name,
        )
        data = _release_payload_to_data(payload, asset) if asset else None

    if not data:
        try:
            req_recent = _github_api_request(f'https://api.github.com/repos/{repo}/releases?per_page=10')
            recent_payload = _json_from_url(req_recent)
        except Exception:
            recent_payload = []
        for release_payload in (recent_payload or []):
            if not isinstance(release_payload, dict):
                continue
            release_assets = release_payload.get('assets') or []
            if not isinstance(release_assets, list):
                continue
            release_asset = _pick_release_asset(
                release_assets,
                direct_exe_only=direct_exe_only,
                preferred_name=preferred_name,
            )
            if not release_asset:
                continue
            data = _release_payload_to_data(release_payload, release_asset)
            if data:
                break
    if not data:
        return None

    _release_cache[cache_key] = {'ts_ms': now, 'data': data}
    return data


def _fetch_release_asset_bytes(asset_id: int, browser_download_url: str = '') -> bytes | None:
    repo = _release_repo()
    if not repo or asset_id <= 0:
        return None

    import urllib.request as _ureq
    import urllib.error as _uerr

    class _NoRedirect(_ureq.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            return None

    req = _github_api_request(
        f'https://api.github.com/repos/{repo}/releases/assets/{asset_id}',
        accept='application/octet-stream',
    )
    s3_url = ''
    try:
        opener = _ureq.build_opener(_NoRedirect)
        with opener.open(req, timeout=30) as resp:
            return resp.read()
    except _uerr.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            s3_url = exc.headers.get('Location', '')
    except Exception:
        pass

    if s3_url:
        try:
            with _ureq.urlopen(s3_url, timeout=120) as resp:  # nosec B310
                return resp.read()
        except Exception:
            pass

    try:
        direct_req = _github_api_request(
            f'https://api.github.com/repos/{repo}/releases/assets/{asset_id}',
            accept='application/octet-stream',
        )
        with _ureq.urlopen(direct_req, timeout=120) as resp:  # nosec B310
            return resp.read()
    except Exception:
        pass

    if browser_download_url:
        try:
            with _ureq.urlopen(_github_api_request(browser_download_url), timeout=120) as resp:  # nosec B310
                return resp.read()
        except Exception:
            pass

    return None


def _latest_release_sha256(release: dict) -> str | None:
    digest = str(release.get('sha256') or '').strip().lower()
    if digest:
        return digest

    asset_id = int(release.get('assetId') or 0)
    browser_download_url = str(release.get('browserDownloadUrl') or '').strip()
    asset_bytes = _fetch_release_asset_bytes(asset_id, browser_download_url)
    if not asset_bytes:
        return None

    digest = hashlib.sha256(asset_bytes).hexdigest()
    release['sha256'] = digest
    cache_key = 'direct_exe' if _is_direct_client_asset_name(str(release.get('assetName') or '')) else 'normal'
    bucket = _release_cache.get(cache_key) or {'ts_ms': 0, 'data': None}
    bucket['data'] = release
    _release_cache[cache_key] = bucket
    return digest


def _build_download_token(asset_id: int, asset_name: str, extra: dict | None = None) -> str:
    ttl = int(current_app.config.get('DOWNLOAD_URL_TTL_SECONDS', 900))
    exp = _unix_ms() + (max(60, ttl) * 1000)
    payload = {
        'v': 1,
        'asset_id': int(asset_id),
        'asset_name': str(asset_name),
        'exp': int(exp),
    }
    if isinstance(extra, dict):
        payload.update(extra)
    token = _pack_signed_json(payload)
    return token


def _build_download_link(asset_id: int, asset_name: str, extra: dict | None = None) -> str:
    token = _build_download_token(asset_id, asset_name, extra=extra)
    return f'/api/client/download?token={quote(token, safe="")}'


def _public_api_root() -> str:
    explicit = str(current_app.config.get('PUBLIC_API_URL', '')).strip().rstrip('/')
    if explicit:
        return explicit
    return request.url_root.rstrip('/')


def _secure_install_allowed(license_row: License | None) -> bool:
    if license_row is None or license_row.is_revoked or _is_expired(license_row):
        return False
    return _plan_is_pro(_license_plan(license_row))


def _active_full_client_license(user: dict) -> License | None:
    active = _choose_summary_license(_licenses_for_user(user))
    if not active or not active.is_active() or active.tier == 'standalone':
        return None
    return active


def _launch_command_ttl_seconds() -> int:
    return max(60, int(current_app.config.get('LAUNCH_COMMAND_TTL_SECONDS', 300)))


def _build_launch_token(license_row: License, discord_id: str) -> str:
    return _pack_signed_json({
        'v': 1,
        'typ': 'divine_launch',
        'lid': int(license_row.id),
        'uid': str(discord_id or '')[:64],
        'kp': str(license_row.key or '')[:4].upper(),
        'exp': _unix_ms() + (_launch_command_ttl_seconds() * 1000),
        'nonce': secrets.token_hex(12),
    })


def _build_powershell_encoded_command(script: str) -> str:
    encoded = base64.b64encode(str(script or '').encode('utf-16le')).decode('ascii')
    return f'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}'


def _build_secure_install_command(download_url: str, expected_sha256: str, asset_name: str) -> str:
    import re as _re

    file_name = _re.sub(r'[^A-Za-z0-9._ -]', '_', str(asset_name or '').strip()) or 'DivineMacros.exe'
    script = (
        "$ProgressPreference='SilentlyContinue';"
        f"$u='{download_url}';"
        f"$h='{str(expected_sha256 or '').lower()}';"
        f"$o=Join-Path $env:TEMP '{file_name}';"
        "Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue;"
        "Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $o;"
        "$a=(Get-FileHash -LiteralPath $o -Algorithm SHA256).Hash.ToLower();"
        "if($a -ne $h){throw 'Integrity check failed. Download blocked.'};"
        "Start-Process -FilePath $o"
    )
    return _build_powershell_encoded_command(script)


def _build_temporary_launch_command(
    download_url: str,
    expected_sha256: str,
    asset_name: str,
    launch_token: str,
    key_prefix: str,
) -> str:
    import re as _re

    file_name = _re.sub(r'[^A-Za-z0-9._ -]', '_', str(asset_name or '').strip()) or 'DivineMacros.exe'
    safe_prefix = _re.sub(r'[^A-Za-z0-9]', '', str(key_prefix or '').strip().upper())[:4] or 'DIVN'
    script = (
        "$ProgressPreference='SilentlyContinue';"
        f"$u='{download_url}';"
        f"$h='{str(expected_sha256 or '').lower()}';"
        f"$t='{launch_token}';"
        f"$k='{safe_prefix}';"
        f"$o=Join-Path $env:TEMP '{file_name}';"
        "Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue;"
        "Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $o;"
        "$a=(Get-FileHash -LiteralPath $o -Algorithm SHA256).Hash.ToLower();"
        "if($a -ne $h){throw 'Integrity check failed. Launch blocked.'};"
        "$p=Start-Process -FilePath $o -ArgumentList @('--launch-token',$t,'--launch-prefix',$k) -PassThru;"
        "Wait-Process -Id $p.Id;"
        "Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue;"
    )
    return _build_powershell_encoded_command(script)


def _bot_api_authorized() -> bool:
    bearer = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    alt = request.headers.get('X-API-Token', '').strip()
    legacy = request.headers.get('x-bot-secret', '').strip()
    expected = str(current_app.config.get('BOT_API_TOKEN', '')).strip()
    secret = str(current_app.config.get('BOT_API_SECRET', expected)).strip()
    for value in (bearer, alt, legacy):
        if value and expected and hmac.compare_digest(value, expected):
            return True
        if value and secret and hmac.compare_digest(value, secret):
            return True
    return False


def _rate_limit(name: str, limit: int) -> bool:
    limiter = get_limiter()
    ip = _client_ip()
    if not limiter.check_and_record(f'web:{name}:{ip}', max(5, int(limit)), 60):
        return False
    return limiter.check_and_record(f'web:global:{ip}', int(current_app.config.get('GLOBAL_RPM', 60)), 60)


def _desktop_license_from_request() -> License | None:
    raw = (
        request.headers.get('X-License-Key', '')
        or request.headers.get('X-Auth-License', '')
        or (request.get_json(silent=True) or {}).get('license_key', '')
        or request.args.get('license_key', '')
    )
    raw = str(raw or '').strip()
    if not raw:
        return None
    try:
        from auth.routes import _lookup_license_by_key
        return _lookup_license_by_key(raw)
    except Exception:
        return None


def _desktop_staff_context(required_role: str = 'moderator'):
    item = _desktop_license_from_request()
    if item is None:
        return None, (jsonify({'ok': False, 'error': 'License key required', 'reason': 'not_logged_in'}), 401)
    if bool(item.is_revoked) or _is_expired(item):
        return None, (jsonify({'ok': False, 'error': 'License is inactive', 'reason': 'invalid_key'}), 401)

    role = _license_role(item)
    allowed = role == 'admin' or (required_role == 'moderator' and role == 'moderator')
    if not allowed:
        return None, (jsonify({'ok': False, 'error': 'Admin access required', 'reason': 'not_admin', 'role': role}), 403)

    return {'license': item, 'role': role}, None


def _desktop_admin_license_rows() -> list[License]:
    rows = License.query.order_by(License.id.desc()).limit(5000).all()
    return [row for row in rows if _license_role(row) == 'admin']


def _desktop_banned_license_rows() -> list[License]:
    return License.query.filter_by(is_revoked=True).order_by(License.id.desc()).limit(5000).all()


def _desktop_admin_item(row: License) -> dict:
    meta = row.extra_metadata or {}
    return {
        'licenseKey': str(row.key or ''),
        'note': str(meta.get('admin_note') or meta.get('notes') or ''),
        'addedAt': _license_created_iso(row),
        'updatedAt': _license_created_iso(row),
    }


def _desktop_ban_item(row: License) -> dict:
    meta = row.extra_metadata or {}
    return {
        'licenseKey': str(row.key or ''),
        'reason': str(meta.get('ban_reason') or meta.get('notes') or ''),
        'bannedAt': str(meta.get('banned_at') or _license_created_iso(row) or ''),
        'updatedAt': str(meta.get('banned_at') or _license_created_iso(row) or ''),
    }


@web_bp.route('/api/desktop/admin/status', methods=['GET', 'POST'])
def desktop_admin_status():
    item = _desktop_license_from_request()
    if item is None:
        return jsonify({'ok': True, 'isAdmin': False, 'role': 'customer', 'endpoint': '/api/desktop/admin', 'reason': 'not_logged_in'}), 200
    if bool(item.is_revoked) or _is_expired(item):
        return jsonify({'ok': True, 'isAdmin': False, 'role': 'customer', 'endpoint': '/api/desktop/admin', 'reason': 'invalid_key'}), 200
    role = _license_role(item)
    return jsonify({
        'ok': True,
        'isAdmin': role == 'admin',
        'role': role,
        'endpoint': '/api/desktop/admin',
        'reason': '' if role == 'admin' else 'not_admin',
    }), 200


@web_bp.route('/api/desktop/admin/admins', methods=['GET'])
def desktop_admin_list_admins():
    _, err = _desktop_staff_context('admin')
    if err:
        return err
    limit = max(1, min(int(request.args.get('limit', 200) or 200), 500))
    admins = [_desktop_admin_item(row) for row in _desktop_admin_license_rows()[:limit]]
    return jsonify({'ok': True, 'admins': admins}), 200


@web_bp.route('/api/desktop/admin/admins', methods=['POST'])
def desktop_admin_add_admin():
    actor, err = _desktop_staff_context('admin')
    if err:
        return err
    data = request.get_json(silent=True) or {}
    raw_key = str(data.get('key') or '').strip()
    note = str(data.get('note') or '').strip()[:400]
    if not raw_key:
        return jsonify({'ok': False, 'error': 'License key required'}), 400
    from auth.routes import _lookup_license_by_key
    target = _lookup_license_by_key(raw_key)
    if target is None:
        return jsonify({'ok': False, 'error': 'License not found'}), 404
    meta = target.extra_metadata or {}
    meta['access_role'] = 'admin'
    if note:
        meta['admin_note'] = note
    target.extra_metadata = meta
    target.session_nonce = secrets.token_hex(16)
    db.session.commit()
    audit_event('desktop.admin.add.ok', ip=_client_ip(), actor=actor['license'].id, target=target.id)
    return jsonify({'ok': True, 'item': _desktop_admin_item(target)}), 200


@web_bp.route('/api/desktop/admin/admins/<path:license_key>', methods=['DELETE'])
def desktop_admin_remove_admin(license_key: str):
    actor, err = _desktop_staff_context('admin')
    if err:
        return err
    from auth.routes import _lookup_license_by_key
    target = _lookup_license_by_key(license_key)
    if target is None:
        return jsonify({'ok': False, 'error': 'License not found'}), 404
    meta = target.extra_metadata or {}
    role = str(meta.get('access_role') or meta.get('role') or 'customer').strip().lower()
    if role == 'admin':
        meta['access_role'] = 'customer'
        meta.pop('admin_note', None)
        target.extra_metadata = meta
        target.session_nonce = secrets.token_hex(16)
        db.session.commit()
    audit_event('desktop.admin.remove.ok', ip=_client_ip(), actor=actor['license'].id, target=target.id)
    return jsonify({'ok': True}), 200


@web_bp.route('/api/desktop/admin/bans', methods=['GET'])
def desktop_admin_list_bans():
    _, err = _desktop_staff_context('admin')
    if err:
        return err
    limit = max(1, min(int(request.args.get('limit', 200) or 200), 500))
    bans = [_desktop_ban_item(row) for row in _desktop_banned_license_rows()[:limit]]
    return jsonify({'ok': True, 'bans': bans}), 200


@web_bp.route('/api/desktop/admin/bans', methods=['POST'])
def desktop_admin_ban():
    actor, err = _desktop_staff_context('admin')
    if err:
        return err
    data = request.get_json(silent=True) or {}
    raw_key = str(data.get('key') or '').strip()
    reason = str(data.get('reason') or '').strip()[:400]
    if not raw_key:
        return jsonify({'ok': False, 'error': 'License key required'}), 400
    from auth.routes import _lookup_license_by_key
    target = _lookup_license_by_key(raw_key)
    if target is None:
        return jsonify({'ok': False, 'error': 'License not found'}), 404
    meta = target.extra_metadata or {}
    meta['ban_reason'] = reason or 'Banned by Divine Macros admin tools'
    meta['banned_at'] = _utc_now().isoformat()
    target.extra_metadata = meta
    target.is_revoked = True
    target.session_nonce = secrets.token_hex(16)
    db.session.commit()
    audit_event('desktop.admin.ban.ok', ip=_client_ip(), actor=actor['license'].id, target=target.id)
    return jsonify({'ok': True, 'item': _desktop_ban_item(target)}), 200


@web_bp.route('/api/desktop/admin/bans/<path:license_key>', methods=['DELETE'])
def desktop_admin_unban(license_key: str):
    actor, err = _desktop_staff_context('admin')
    if err:
        return err
    from auth.routes import _lookup_license_by_key
    target = _lookup_license_by_key(license_key)
    if target is None:
        return jsonify({'ok': False, 'error': 'License not found'}), 404
    meta = target.extra_metadata or {}
    meta.pop('ban_reason', None)
    meta.pop('banned_at', None)
    target.extra_metadata = meta
    target.is_revoked = False
    target.session_nonce = secrets.token_hex(16)
    db.session.commit()
    audit_event('desktop.admin.unban.ok', ip=_client_ip(), actor=actor['license'].id, target=target.id)
    return jsonify({'ok': True}), 200


@web_bp.route('/api/desktop/admin/stats', methods=['GET'])
def desktop_admin_stats():
    _, err = _desktop_staff_context('admin')
    if err:
        return err
    marketplace_posts = 0
    try:
        marketplace_posts = len(_community_read_store().get('entries') or [])
    except Exception:
        marketplace_posts = 0
    return jsonify({
        'ok': True,
        'counts': {
            'posts': marketplace_posts,
            'bans': len(_desktop_banned_license_rows()),
            'audit': len(_desktop_admin_license_rows()),
        }
    }), 200


@web_bp.route('/api/desktop/admin/security', methods=['GET'])
def desktop_admin_security():
    _, err = _desktop_staff_context('admin')
    if err:
        return err
    return jsonify({
        'ok': True,
        'integrityOk': True,
        'integrityFailures': [],
        'integrityLastCheckAt': _unix_ms(),
        'runtimeUnlocked': True,
        'runtimeLeaseUntil': 0,
    }), 200


def _community_store_path() -> Path:
    explicit = str(current_app.config.get('COMMUNITY_STORE_PATH', '')).strip()
    if explicit:
        return Path(explicit)
    instance_path = Path(getattr(current_app, 'instance_path', '') or '.')
    return instance_path / 'macro_marketplace.json'


def _community_empty_store() -> dict:
    return {'version': 2, 'entries': [], 'users': {}, 'tickets': [], 'chat': []}


def _community_read_store() -> dict:
    path = _community_store_path()
    try:
        if not path.exists():
            return _community_empty_store()
        with path.open('r', encoding='utf-8') as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return _community_empty_store()
        entries = data.get('entries')
        if not isinstance(entries, list):
            data['entries'] = []
        if not isinstance(data.get('users'), dict):
            data['users'] = {}
        if not isinstance(data.get('tickets'), list):
            data['tickets'] = []
        if not isinstance(data.get('chat'), list):
            data['chat'] = []
        return data
    except Exception:
        return _community_empty_store()


def _community_write_store(data: dict) -> None:
    path = _community_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f'.{secrets.token_hex(8)}.tmp')
    payload = {
        'version': 2,
        'entries': list(data.get('entries') or []),
        'users': dict(data.get('users') or {}),
        'tickets': list(data.get('tickets') or []),
        'chat': list(data.get('chat') or [])[-300:],
        'chatClearedAt': str(data.get('chatClearedAt') or ''),
        'updatedAt': _utc_now().isoformat(),
    }
    with _community_store_lock:
        try:
            with tmp.open('w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, separators=(',', ':'))
                fh.flush()
            tmp.replace(path)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass


def _community_text(value: object, limit: int, default: str = '') -> str:
    text = str(value or default).strip()
    return text[:max(1, limit)]


def _community_slug(value: str) -> str:
    import re as _re
    base = _re.sub(r'[^a-zA-Z0-9]+', '-', str(value or '').strip().lower()).strip('-')
    return (base[:42] or 'macro') + '-' + secrets.token_hex(4)


def _community_display_name(value: object, default: str = 'Divine User') -> str:
    text = re.sub(r'[^a-zA-Z0-9_. -]+', '', str(value or default)).strip()
    text = re.sub(r'\s+', ' ', text)
    return (text[:32].strip() or default)[:32]


def _community_actor_context() -> dict | None:
    user, err = _dashboard_user_or_401()
    if not err and user:
        uid = str(user.get('id') or '').strip()
        if uid:
            return {
                'discordId': uid,
                'discordUsername': str(user.get('globalName') or user.get('username') or '').strip(),
                'avatarUrl': str(user.get('avatarUrl') or '').strip(),
                'role': _verified_role_for_discord(uid),
                'source': 'dashboard',
            }

    item = _desktop_license_from_request()
    if item is not None and not bool(item.is_revoked) and not _is_expired(item):
        meta = item.extra_metadata or {}
        uid = str(meta.get('discord_id') or meta.get('discordId') or '').strip()
        if uid:
            return {
                'discordId': uid,
                'discordUsername': str(meta.get('discord_username') or meta.get('discordUsername') or '').strip(),
                'avatarUrl': str(meta.get('discord_avatar') or meta.get('avatarUrl') or '').strip(),
                'role': _license_role(item),
                'source': 'license',
            }
    return None


def _community_pro_context():
    actor = _community_actor_context()
    item = _desktop_license_from_request()
    if item is None and actor and actor.get('discordId'):
        wanted = str(actor.get('discordId') or '').strip()
        rows = License.query.filter(License.is_revoked.is_(False)).order_by(License.id.desc()).limit(5000).all()
        item = next((
            row for row in rows
            if str((row.extra_metadata or {}).get('discord_id') or (row.extra_metadata or {}).get('discordId') or '').strip() == wanted
            and not _is_expired(row)
            and _plan_is_pro(_license_plan(row))
        ), None)
    if item is None or bool(item.is_revoked) or _is_expired(item) or not _plan_is_pro(_license_plan(item)):
        return actor, (
            jsonify({
                'ok': False,
                'error': 'pro_required',
                'locked': True,
                'reason': 'Divine Community is available with Pro Monthly or Pro Lifetime.',
            }),
            403,
        )
    return actor, None


def _verified_role_for_discord(discord_id: str) -> str:
    wanted = str(discord_id or '').strip()
    if not wanted:
        return 'customer'
    rows = (
        License.query
        .filter(License._metadata.like(f'%"discord_id": "{wanted}"%'))
        .filter(License.is_revoked.is_(False))
        .order_by(License.id.desc())
        .limit(20)
        .all()
    )
    best = 'customer'
    rank = {'customer': 0, 'moderator': 1, 'admin': 2}
    for row in rows:
        meta = row.extra_metadata or {}
        linked = str(meta.get('discord_id') or meta.get('discordId') or '').strip()
        if linked != wanted or _is_expired(row):
            continue
        role = _license_role(row)
        if rank[role] > rank[best]:
            best = role
    return best


def _community_default_profile(actor: dict | None) -> dict:
    actor = actor or {}
    name = _community_display_name(actor.get('discordUsername') or 'Divine User')
    return {
        'discordId': str(actor.get('discordId') or '').strip(),
        'discordUsername': str(actor.get('discordUsername') or '').strip(),
        'avatarUrl': str(actor.get('avatarUrl') or '').strip(),
        'displayName': name,
        'publicDiscord': True,
        'updatedAt': _utc_now().isoformat(),
    }


def _community_profile_record(actor: dict | None) -> CommunityProfile | None:
    actor = actor or {}
    discord_id = str(actor.get('discordId') or '').strip()
    if not discord_id:
        return None
    return db.session.get(CommunityProfile, discord_id)


def _community_profile_public(profile: dict | None) -> dict:
    p = profile if isinstance(profile, dict) else {}
    public_discord = bool(p.get('publicDiscord', True))
    out = {
        'displayName': _community_display_name(p.get('displayName') or p.get('discordUsername') or 'Divine User'),
        'publicDiscord': public_discord,
    }
    if public_discord:
        out['discordId'] = str(p.get('discordId') or '').strip()
        out['discordUsername'] = str(p.get('discordUsername') or '').strip()
        out['avatarUrl'] = str(p.get('avatarUrl') or '').strip()
    return out


def _community_profile_name_taken(store: dict, display_name: str, owner_id: str) -> bool:
    wanted = _community_display_name(display_name).lower()
    users = store.get('users') if isinstance(store.get('users'), dict) else {}
    for uid, profile in users.items():
        if str(uid) == str(owner_id):
            continue
        if _community_display_name((profile or {}).get('displayName')).lower() == wanted:
            return True
    return False


def _community_payload_stats(payload: dict) -> dict:
    wrapped = payload.get('payload') if isinstance(payload.get('payload'), dict) else payload
    cfg = wrapped.get('config') if isinstance(wrapped, dict) and isinstance(wrapped.get('config'), dict) else None
    macros = []
    if isinstance(wrapped, dict) and isinstance(wrapped.get('customMacros'), list):
        macros = wrapped.get('customMacros') or []
    elif isinstance(cfg, dict) and isinstance(cfg.get('customMacros'), list):
        macros = cfg.get('customMacros') or []
    step_count = 0
    for macro in macros:
        if isinstance(macro, dict) and isinstance(macro.get('sequence'), list):
            step_count += len(macro.get('sequence') or [])
    return {
        'macroCount': len(macros),
        'stepCount': step_count,
        'hasConfig': bool(cfg or (isinstance(wrapped, dict) and any(k in wrapped for k in ('sa', 'da', 'ap', 'hc', 'customMacros')))),
    }


def _community_normalize_submission(raw: dict) -> dict:
    payload = raw if isinstance(raw, dict) else {}
    title = _community_text(payload.get('title') or payload.get('name'), 80, 'Untitled Macro')
    description = _community_text(payload.get('description') or payload.get('desc'), 280, '')
    author = _community_text(payload.get('author') or payload.get('user') or payload.get('by'), 40, 'Anonymous')
    tags_raw = payload.get('tags')
    if not isinstance(tags_raw, list):
        tags_raw = ['composer']
    tags = [_community_text(tag, 24) for tag in tags_raw]
    tags = [tag for tag in tags if tag][:10]
    if 'composer' not in [tag.lower() for tag in tags]:
        tags.insert(0, 'composer')
    now = _utc_now().isoformat()
    entry_payload = json.loads(json.dumps(payload))
    stats = _community_payload_stats(entry_payload)
    return {
        'id': _community_slug(title),
        'shareKey': secrets.token_urlsafe(7).replace('-', '').replace('_', '')[:10].upper(),
        'name': title,
        'description': description,
        'author': author,
        'createdAt': now,
        'updatedAt': now,
        'tags': tags,
        'payload': entry_payload,
        'downloads': 0,
        'likes': 0,
        'likedBy': [],
        'featured': False,
        'featuredBy': '',
        **stats,
    }


def _community_public_entry(entry: dict, include_payload: bool = False) -> dict:
    profile = entry.get('authorProfile') if isinstance(entry.get('authorProfile'), dict) else None
    out = {
        'id': str(entry.get('id') or ''),
        'name': str(entry.get('name') or 'Untitled Macro'),
        'description': str(entry.get('description') or ''),
        'author': str(entry.get('author') or 'Anonymous'),
        'authorProfile': _community_profile_public(profile) if profile else {},
        'createdAt': str(entry.get('createdAt') or ''),
        'updatedAt': str(entry.get('updatedAt') or ''),
        'tags': list(entry.get('tags') or []),
        'downloads': int(entry.get('downloads') or 0),
        'likes': int(entry.get('likes') or 0),
        'shareKey': str(entry.get('shareKey') or ''),
        'featured': bool(entry.get('featured')),
        'featuredBy': str(entry.get('featuredBy') or ''),
        'macroCount': int(entry.get('macroCount') or 0),
        'stepCount': int(entry.get('stepCount') or 0),
        'hasConfig': bool(entry.get('hasConfig')),
    }
    if include_payload:
        out['payload'] = entry.get('payload') or {}
    return out


@web_bp.route('/api/marketplace/profile', methods=['GET', 'POST'])
@web_bp.route('/api/community/profile', methods=['GET', 'POST'])
def community_profile_proxy():
    actor, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    if not actor or not actor.get('discordId'):
        return jsonify({'ok': False, 'error': 'Discord account required'}), 401

    discord_id = str(actor.get('discordId') or '').strip()
    record = _community_profile_record(actor)
    default = _community_default_profile(actor)
    if record is None:
        initial_name = default['displayName']
        if CommunityProfile.query.filter(db.func.lower(CommunityProfile.display_name) == initial_name.lower()).first():
            initial_name = _community_display_name(f"{initial_name}-{discord_id[-4:]}")
        record = CommunityProfile(
            discord_id=discord_id,
            discord_username=default['discordUsername'],
            avatar_url=default['avatarUrl'],
            display_name=initial_name,
            public_discord=True,
        )
        db.session.add(record)

    record.discord_username = str(actor.get('discordUsername') or record.discord_username or '').strip()
    record.avatar_url = str(actor.get('avatarUrl') or record.avatar_url or '').strip()

    if request.method == 'POST':
        payload = request.get_json(silent=True) or {}
        display_name = _community_display_name(payload.get('displayName') or record.display_name or record.discord_username or 'Divine User')
        if len(display_name) < 3:
            return jsonify({'ok': False, 'error': 'Divine username must be at least 3 characters.'}), 400
        taken = (
            CommunityProfile.query
            .filter(db.func.lower(CommunityProfile.display_name) == display_name.lower())
            .filter(CommunityProfile.discord_id != discord_id)
            .first()
        )
        if taken is not None:
            return jsonify({'ok': False, 'error': 'That Divine username is already taken.'}), 409
        record.display_name = display_name
        record.public_discord = bool(payload.get('publicDiscord', True))

    db.session.commit()
    current = record.to_dict()

    if request.method == 'POST':
        with _state_lock:
            store = _community_read_store()
            users = store.get('users') if isinstance(store.get('users'), dict) else {}
            users[discord_id] = current
            store['users'] = users
            _community_write_store(store)

    return jsonify({'ok': True, 'profile': current}), 200


@web_bp.route('/api/marketplace/feed', methods=['GET'])
@web_bp.route('/api/community/feed', methods=['GET'])
def community_feed_proxy():
    _, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    query = str(request.args.get('q') or '').strip().lower()
    limit = max(1, min(int(request.args.get('limit', 80) or 80), 200))
    with _state_lock:
        store = _community_read_store()
        entries = list(store.get('entries') or [])
    entries.sort(key=lambda item: str(item.get('createdAt') or ''), reverse=True)
    if query:
        entries = [
            item for item in entries
            if query in f"{item.get('name','')} {item.get('description','')} {item.get('author','')} {' '.join(item.get('tags') or [])}".lower()
        ]
    public = [_community_public_entry(item, include_payload=True) for item in entries[:limit]]
    return jsonify({'ok': True, 'entries': public, 'source': 'backend'}), 200


@web_bp.route('/api/marketplace/submit', methods=['POST'])
@web_bp.route('/api/community/submit', methods=['POST'])
def community_submit_proxy():
    actor, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({'ok': False, 'error': 'JSON object required'}), 400
    if not _rate_limit('community_submit', 12):
        return jsonify({'ok': False, 'error': 'Rate limit exceeded'}), 429
    entry = _community_normalize_submission(payload)
    with _state_lock:
        store = _community_read_store()
        if actor and actor.get('discordId'):
            discord_id = str(actor.get('discordId') or '').strip()
            users = store.get('users') if isinstance(store.get('users'), dict) else {}
            record = _community_profile_record(actor)
            profile = dict(record.to_dict() if record else (users.get(discord_id) or _community_default_profile(actor)))
            profile['discordId'] = discord_id
            profile['discordUsername'] = str(actor.get('discordUsername') or profile.get('discordUsername') or '').strip()
            profile['avatarUrl'] = str(actor.get('avatarUrl') or profile.get('avatarUrl') or '').strip()
            profile['displayName'] = _community_display_name(profile.get('displayName') or profile.get('discordUsername') or 'Divine User')
            profile['publicDiscord'] = bool(profile.get('publicDiscord', True))
            users[discord_id] = profile
            store['users'] = users
            public_profile = _community_profile_public(profile)
            entry['authorProfile'] = public_profile
            entry['ownerDiscordId'] = discord_id
            entry['author'] = public_profile.get('displayName', 'Divine User')
        entries = list(store.get('entries') or [])
        entries.insert(0, entry)
        store['entries'] = entries[:1000]
        _community_write_store(store)
    return jsonify({'ok': True, 'entry': _community_public_entry(entry, include_payload=True)}), 201


def _community_feature_allowed(actor: dict | None) -> bool:
    actor = actor or {}
    discord_id = str(actor.get('discordId') or '').strip()
    username = str(actor.get('discordUsername') or '').strip().lower()
    configured = {
        value.strip()
        for value in str(current_app.config.get('COMMUNITY_FEATURED_DISCORD_IDS', '')).split(',')
        if value.strip()
    }
    # Project owner account retained as a deployment-safe default. Additional
    # curators should be configured through COMMUNITY_FEATURED_DISCORD_IDS.
    configured.add('1303266095331016724')
    if discord_id and discord_id in configured:
        return True
    if username == '198m':
        return True
    staff, err = _desktop_staff_context('admin')
    return bool(staff and not err)


@web_bp.route('/api/marketplace/<post_id>/vote', methods=['POST'])
@web_bp.route('/api/community/<post_id>/vote', methods=['POST'])
def community_vote(post_id: str):
    actor, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    if not actor or not actor.get('discordId'):
        return jsonify({'ok': False, 'error': 'Discord account required'}), 401
    voter_id = str(actor.get('discordId') or '').strip()
    with _state_lock:
        store = _community_read_store()
        entries = list(store.get('entries') or [])
        entry = next((item for item in entries if str(item.get('id') or '') == post_id), None)
        if entry is None:
            return jsonify({'ok': False, 'error': 'Post not found'}), 404
        liked_by = {str(value) for value in (entry.get('likedBy') or []) if str(value)}
        liked = voter_id not in liked_by
        if liked:
            liked_by.add(voter_id)
        else:
            liked_by.discard(voter_id)
        entry['likedBy'] = sorted(liked_by)
        entry['likes'] = len(liked_by)
        entry['updatedAt'] = _utc_now().isoformat()
        store['entries'] = entries
        _community_write_store(store)
    return jsonify({'ok': True, 'liked': liked, 'likes': len(liked_by)}), 200


@web_bp.route('/api/marketplace/<post_id>/feature', methods=['POST'])
@web_bp.route('/api/community/<post_id>/feature', methods=['POST'])
def community_feature(post_id: str):
    actor, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    if not actor or not _community_feature_allowed(actor):
        return jsonify({'ok': False, 'error': 'Featured curator access required'}), 403
    payload = request.get_json(silent=True) or {}
    requested = payload.get('featured')
    with _state_lock:
        store = _community_read_store()
        entries = list(store.get('entries') or [])
        entry = next((item for item in entries if str(item.get('id') or '') == post_id), None)
        if entry is None:
            return jsonify({'ok': False, 'error': 'Post not found'}), 404
        featured = bool(requested) if requested is not None else not bool(entry.get('featured'))
        entry['featured'] = featured
        entry['featuredBy'] = str(actor.get('discordUsername') or actor.get('discordId') or '') if featured else ''
        entry['updatedAt'] = _utc_now().isoformat()
        store['entries'] = entries
        _community_write_store(store)
    return jsonify({'ok': True, 'featured': featured, 'entry': _community_public_entry(entry, include_payload=True)}), 200


@web_bp.route('/api/marketplace/key/<share_key>', methods=['GET'])
@web_bp.route('/api/community/key/<share_key>', methods=['GET'])
def community_share_key(share_key: str):
    _, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    wanted = str(share_key or '').strip().upper()
    with _state_lock:
        entries = list(_community_read_store().get('entries') or [])
    entry = next((item for item in entries if str(item.get('shareKey') or '').upper() == wanted), None)
    if entry is None:
        return jsonify({'ok': False, 'error': 'Share key not found'}), 404
    return jsonify({'ok': True, 'entry': _community_public_entry(entry, include_payload=True)}), 200


@web_bp.route('/api/community/chat', methods=['GET', 'POST'])
@web_bp.route('/api/marketplace/chat', methods=['GET', 'POST'])
def community_chat():
    actor, pro_err = _community_pro_context()
    if pro_err:
        return pro_err
    cutoff = _utc_now() - timedelta(hours=24)
    with _state_lock:
        chat_store = _community_read_store()
        cleared_at = str(chat_store.get('chatClearedAt') or '')
    expired = CommunityChatMessage.query.filter(CommunityChatMessage.created_at <= cutoff).delete(synchronize_session=False)
    if expired:
        cleared_at = _utc_now().isoformat()
        db.session.commit()
        with _state_lock:
            chat_store = _community_read_store()
            chat_store['chatClearedAt'] = cleared_at
            _community_write_store(chat_store)

    if request.method == 'POST':
        if not actor or not actor.get('discordId'):
            return jsonify({'ok': False, 'error': 'Discord account required'}), 401
        if not _rate_limit('community_chat', 30):
            return jsonify({'ok': False, 'error': 'Slow down and try again.'}), 429
        body = _community_text((request.get_json(silent=True) or {}).get('message'), 500, '')
        if not body:
            return jsonify({'ok': False, 'error': 'Message is required'}), 400
        profile = _community_profile_record(actor)
        profile_data = profile.to_dict() if profile else _community_default_profile(actor)
        row = CommunityChatMessage(
            discord_id=str(actor.get('discordId') or ''),
            author=_community_display_name(profile_data.get('displayName') or profile_data.get('discordUsername') or 'Divine User'),
            avatar_url=str(profile_data.get('avatarUrl') or actor.get('avatarUrl') or ''),
            role=str(actor.get('role') or 'customer'),
            message=body,
        )
        db.session.add(row)
        db.session.commit()
        return jsonify({'ok': True, 'message': row.to_dict(), 'expiredCount': expired}), 201

    limit = max(1, min(int(request.args.get('limit', 80) or 80), 150))
    rows = (
        CommunityChatMessage.query
        .filter(CommunityChatMessage.created_at > cutoff)
        .order_by(CommunityChatMessage.created_at.desc())
        .limit(limit)
        .all()
    )
    chat = [row.to_dict() for row in reversed(rows)]
    chat_discord_ids = {
        str(entry.get('discordId') or '').strip()
        for entry in chat
        if str(entry.get('discordId') or '').strip()
    }
    roles = {discord_id: _verified_role_for_discord(discord_id) for discord_id in chat_discord_ids}
    for entry in chat:
        entry['role'] = roles.get(str(entry.get('discordId') or ''), 'customer')
    return jsonify({
        'ok': True,
        'messages': chat,
        'retentionHours': 24,
        'expiredCount': expired,
        'clearedAt': cleared_at,
    }), 200


@web_bp.route('/api/client/notifications', methods=['GET'])
def client_notifications():
    if not _rate_limit('client_notifications', 90):
        return jsonify({'ok': False, 'error': 'Rate limit exceeded'}), 429
    item = _desktop_license_from_request()
    if item is None or bool(item.is_revoked) or _is_expired(item):
        return jsonify({'ok': False, 'error': 'Active license required'}), 401

    meta = item.extra_metadata or {}
    discord_id = str(meta.get('discord_id') or meta.get('discordId') or '').strip()
    now = _utc_now()
    rows = (
        ClientNotification.query
        .filter(ClientNotification.is_active.is_(True))
        .filter(
            or_(
                ClientNotification.expires_at.is_(None),
                ClientNotification.expires_at > now,
            )
        )
        .order_by(ClientNotification.created_at.desc())
        .limit(100)
        .all()
    )
    visible = [
        row.to_dict()
        for row in rows
        if row.audience == 'all'
        or (row.audience == 'discord' and discord_id and row.discord_id == discord_id)
    ]
    return jsonify({'ok': True, 'notifications': visible[:50]}), 200


@web_bp.route('/api/client/locks', methods=['GET'])
def client_feature_locks():
    if not _rate_limit('client_feature_locks', 120):
        return jsonify({'ok': False, 'error': 'Rate limit exceeded'}), 429
    item = _desktop_license_from_request()
    if item is None or bool(item.is_revoked) or _is_expired(item):
        return jsonify({'ok': False, 'error': 'Active license required'}), 401

    rows = (
        ClientFeatureLock.query
        .filter(ClientFeatureLock.is_locked.is_(True))
        .order_by(ClientFeatureLock.category.asc())
        .all()
    )
    return jsonify({'ok': True, 'locks': [row.to_dict() for row in rows]}), 200


@web_bp.route('/api/community/delete', methods=['POST', 'DELETE'])
@web_bp.route('/api/community/moderate/delete', methods=['POST', 'DELETE'])
@web_bp.route('/api/marketplace/delete', methods=['POST', 'DELETE'])
@web_bp.route('/api/marketplace/moderate/delete', methods=['POST', 'DELETE'])
def community_delete_proxy():
    actor, err = _desktop_staff_context('moderator')
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    post_id = str(payload.get('id') or '').strip()
    if not post_id:
        return jsonify({'ok': False, 'error': 'Post id is required'}), 400
    with _state_lock:
        store = _community_read_store()
        entries = list(store.get('entries') or [])
        before = len(entries)
        entries = [item for item in entries if str(item.get('id') or '') != post_id]
        if len(entries) == before:
            return jsonify({'ok': False, 'error': 'Post not found'}), 404
        store['entries'] = entries
        _community_write_store(store)
    audit_event('community.delete.ok', ip=_client_ip(), actor=actor['license'].id, post_id=post_id)
    return jsonify({'ok': True, 'id': post_id}), 200


SUPPORT_TICKET_CATEGORIES = {
    'app_bug': 'App Bug Report',
    'hwid_reset': 'HWID Reset',
    'product_keys': 'Product Keys',
    'general_support': 'General Support',
    'business_affiliate': 'Business & Affiliate',
    'report_user': 'Report A User',
}


def _support_ticket_public(ticket: dict, *, admin: bool = False) -> dict:
    messages = ticket.get('messages') if isinstance(ticket.get('messages'), list) else []
    out = {
        'id': str(ticket.get('id') or ''),
        'category': str(ticket.get('category') or 'general_support'),
        'categoryLabel': SUPPORT_TICKET_CATEGORIES.get(str(ticket.get('category') or ''), 'General Support'),
        'subject': str(ticket.get('subject') or ''),
        'status': str(ticket.get('status') or 'open'),
        'createdAt': str(ticket.get('createdAt') or ''),
        'updatedAt': str(ticket.get('updatedAt') or ''),
        'messages': messages,
    }
    if admin:
        out['user'] = ticket.get('user') if isinstance(ticket.get('user'), dict) else {}
    return out


@web_bp.route('/api/dashboard/tickets', methods=['GET', 'POST'])
def dashboard_tickets():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    uid = str(user.get('id') or '').strip()
    if not uid:
        return jsonify({'ok': False, 'error': 'Discord account required'}), 401
    if request.method == 'GET':
        with _state_lock:
            store = _community_read_store()
            tickets = [
                _support_ticket_public(item)
                for item in list(store.get('tickets') or [])
                if str(((item.get('user') or {}).get('id')) or '') == uid
            ]
        tickets.sort(key=lambda item: item.get('updatedAt') or '', reverse=True)
        return jsonify({'ok': True, 'tickets': tickets}), 200

    payload = request.get_json(silent=True) or {}
    category = str(payload.get('category') or 'general_support').strip()
    if category not in SUPPORT_TICKET_CATEGORIES:
        category = 'general_support'
    subject = _community_text(payload.get('subject'), 90, SUPPORT_TICKET_CATEGORIES[category])
    body = _community_text(payload.get('message') or payload.get('body'), 1800, '')
    if len(body) < 8:
        return jsonify({'ok': False, 'error': 'Add a little more detail before submitting.'}), 400
    now = _utc_now().isoformat()
    ticket = {
        'id': 'ticket-' + secrets.token_hex(6),
        'category': category,
        'subject': subject,
        'status': 'open',
        'createdAt': now,
        'updatedAt': now,
        'user': {
            'id': uid,
            'username': str(user.get('globalName') or user.get('username') or '').strip(),
            'email': str(user.get('email') or '').strip().lower(),
            'avatarUrl': str(user.get('avatarUrl') or '').strip(),
        },
        'messages': [{
            'id': secrets.token_hex(6),
            'authorRole': 'user',
            'authorName': str(user.get('globalName') or user.get('username') or 'Customer'),
            'body': body,
            'createdAt': now,
        }],
    }
    with _state_lock:
        store = _community_read_store()
        tickets = list(store.get('tickets') or [])
        tickets.insert(0, ticket)
        store['tickets'] = tickets[:1000]
        _community_write_store(store)
    audit_event('web.dashboard.ticket.created', ip=_client_ip(), discord_id=uid, category=category)
    return jsonify({'ok': True, 'ticket': _support_ticket_public(ticket)}), 201


@web_bp.route('/api/dashboard/tickets/<ticket_id>/reply', methods=['POST'])
def dashboard_ticket_reply(ticket_id: str):
    user, err = _dashboard_user_or_401()
    if err:
        return err
    uid = str(user.get('id') or '').strip()
    body = _community_text((request.get_json(silent=True) or {}).get('message'), 1800, '')
    if len(body) < 2:
        return jsonify({'ok': False, 'error': 'Reply cannot be empty.'}), 400
    with _state_lock:
        store = _community_read_store()
        tickets = list(store.get('tickets') or [])
        target = next((item for item in tickets if str(item.get('id') or '') == str(ticket_id) and str(((item.get('user') or {}).get('id')) or '') == uid), None)
        if target is None:
            return jsonify({'ok': False, 'error': 'Ticket not found'}), 404
        now = _utc_now().isoformat()
        target.setdefault('messages', []).append({
            'id': secrets.token_hex(6),
            'authorRole': 'user',
            'authorName': str(user.get('globalName') or user.get('username') or 'Customer'),
            'body': body,
            'createdAt': now,
        })
        target['status'] = 'open'
        target['updatedAt'] = now
        store['tickets'] = tickets
        _community_write_store(store)
    return jsonify({'ok': True, 'ticket': _support_ticket_public(target)}), 200


@web_bp.route('/api/admin/tickets', methods=['GET'])
def admin_list_tickets():
    err, _ = _require_admin_token()
    if err:
        return err
    with _state_lock:
        store = _community_read_store()
        tickets = [_support_ticket_public(item, admin=True) for item in list(store.get('tickets') or [])]
    tickets.sort(key=lambda item: item.get('updatedAt') or '', reverse=True)
    return jsonify({'ok': True, 'tickets': tickets}), 200


@web_bp.route('/api/admin/tickets/<ticket_id>/reply', methods=['POST'])
def admin_reply_ticket(ticket_id: str):
    err, data = _require_admin_token()
    if err:
        return err
    body = _community_text(data.get('message'), 1800, '')
    status = str(data.get('status') or 'answered').strip().lower()
    if status not in {'open', 'answered', 'closed'}:
        status = 'answered'
    if len(body) < 2:
        return jsonify({'ok': False, 'error': 'Reply cannot be empty.'}), 400
    with _state_lock:
        store = _community_read_store()
        tickets = list(store.get('tickets') or [])
        target = next((item for item in tickets if str(item.get('id') or '') == str(ticket_id)), None)
        if target is None:
            return jsonify({'ok': False, 'error': 'Ticket not found'}), 404
        now = _utc_now().isoformat()
        target.setdefault('messages', []).append({
            'id': secrets.token_hex(6),
            'authorRole': 'admin',
            'authorName': 'Divine Support',
            'body': body,
            'createdAt': now,
        })
        target['status'] = status
        target['updatedAt'] = now
        store['tickets'] = tickets
        _community_write_store(store)
    audit_event('admin.ticket.reply', ip=_client_ip(), ticket_id=ticket_id, status=status)
    return jsonify({'ok': True, 'ticket': _support_ticket_public(target, admin=True)}), 200


# Auth Event Logging (for Discord bot security reporting)
_auth_events = []  # Circular buffer of recent auth events
_auth_events_max = 1000


def _push_auth_event(event: dict) -> None:
    """Push an authentication event to the log buffer."""
    with _state_lock:
        _auth_events.append({
            'timestamp': _unix_ms(),
            **event
        })
        if len(_auth_events) > _auth_events_max:
            _auth_events.pop(0)


@web_bp.route('/api/internal/auth/event', methods=['POST'])
def internal_auth_event_log():
    """
    Log an authentication event. Called by bot or client on auth success/failure.
    Required headers: X-Bot-Secret (bot API secret)
    Payload: {
        "event_type": "login_success" | "login_failed" | "crack_attempt",
        "license_key": "XXXX-XXXX-XXXX-XXXX" (masked or partial),
        "discord_id": "user_id" (optional),
        "ip": "x.x.x.x",
        "details": "message or reason"
    }
    """
    if not _bot_api_authorized():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    event_type = str(data.get('event_type') or '').strip().lower()
    license_key = str(data.get('license_key') or '').strip()
    discord_id = str(data.get('discord_id') or '').strip()
    ip = str(data.get('ip') or _client_ip()).strip()
    details = str(data.get('details') or '').strip()

    if event_type not in ('login_success', 'login_failed', 'crack_attempt'):
        return jsonify({'ok': False, 'error': 'Invalid event_type'}), 400

    if not license_key and not discord_id:
        return jsonify({'ok': False, 'error': 'License key or Discord ID required'}), 400

    event = {
        'event_type': event_type,
        'license_key': license_key[:64],
        'discord_id': discord_id[:32] if discord_id else '',
        'ip': ip,
        'details': details[:500],
        'source': 'bot_api',
    }
    _push_auth_event(event)
    audit_event(f'auth.event.{event_type}', ip=ip, extra=details[:200])

    return jsonify({'ok': True, 'event_id': _unix_ms()}), 200


@web_bp.route('/api/internal/auth/events', methods=['GET'])
def internal_auth_events_list():
    """
    Retrieve recent authentication events (bot use only).
    Query params:
      - limit: max events to return (default 100, max 500)
      - event_type: filter by event type (optional)
    """
    if not _bot_api_authorized():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    limit = max(1, min(int(request.args.get('limit', 100) or 100), 500))
    filter_type = str(request.args.get('event_type') or '').strip().lower()

    with _state_lock:
        events = list(_auth_events)

    if filter_type:
        events = [e for e in events if e.get('event_type') == filter_type]

    # Return most recent events
    events = events[-limit:][::-1]

    return jsonify({
        'ok': True,
        'events': events,
        'count': len(events),
    }), 200


@web_bp.route('/auth/discord/start', methods=['GET'])
@web_bp.route('/api/auth/discord/start', methods=['GET'])
def discord_start():
    if not _rate_limit('discord_start', 90):
        return jsonify({'ok': False, 'error': 'Too many requests'}), 429
    next_path = _safe_next_path(request.args.get('next', ''))
    # [SECURITY HARDENING] If an authenticated dashboard session already
    # exists, avoid unnecessary OAuth loops and bounce straight to target.
    existing_sid, existing_row = _dashboard_session()
    if existing_sid and existing_row:
        existing_token = _build_session_token(existing_sid, existing_row)
        return redirect(_site_redirect_with_token(next_path, existing_token, auth_ok=True), code=302)

    if not _discord_oauth_ready():
        return make_response('Discord OAuth is not configured yet.', 503)

    state = _build_oauth_state(next_path)

    query = urlencode({
        'client_id': str(current_app.config.get('DISCORD_OAUTH_CLIENT_ID', '')).strip(),
        'response_type': 'code',
        'redirect_uri': str(current_app.config.get('DISCORD_OAUTH_REDIRECT_URI', '')).strip(),
        'scope': 'identify email',
        'prompt': 'consent',
        'state': state,
    })
    audit_event('web.oauth.start', ip=_client_ip())
    return redirect(f'https://discord.com/api/oauth2/authorize?{query}', code=302)


@web_bp.route('/auth/discord/callback', methods=['GET'])
@web_bp.route('/api/auth/discord/callback', methods=['GET'])
def discord_callback():
    if not _rate_limit('discord_callback', 90):
        return redirect('/?auth=failed&reason=rate_limit', code=302)
    if not _discord_oauth_ready():
        return redirect('/?auth=failed&reason=oauth_not_configured', code=302)

    err_name = str(request.args.get('error') or '').strip().lower()
    if err_name:
        if err_name == 'access_denied':
            return redirect('/?auth=declined', code=302)
        return redirect('/?auth=failed', code=302)

    code = str(request.args.get('code') or '').strip()
    state = str(request.args.get('state') or '').strip()
    if not code or not state:
        return redirect('/?auth=failed&reason=missing_code_or_state', code=302)

    state_row = _read_oauth_state(state)
    if not state_row:
        return redirect('/?auth=failed&reason=invalid_or_expired_state', code=302)

    token_json = _exchange_discord_code(code)
    access_token = str((token_json or {}).get('access_token') or '').strip()
    if not access_token:
        token_err = str((token_json or {}).get('error') or '').strip().lower()
        token_desc = str((token_json or {}).get('error_description') or '').strip().lower()
        try:
            audit_event(
                'web.oauth.token.failed',
                ip=_client_ip(),
                token_error=token_err[:80] if token_err else '',
                token_desc=token_desc[:120] if token_desc else '',
            )
        except Exception:
            pass
        if token_err:
            reason = f'token_exchange_failed_{token_err}'
        elif token_desc:
            reason = f'token_exchange_failed_{token_desc.replace(" ", "_")[:80]}'
        else:
            reason = 'token_exchange_failed'
        reason = ''.join(ch for ch in reason if ch.isalnum() or ch in {'_', '-'})
        return redirect(f'/?auth=failed&reason={reason}', code=302)

    user_json = _fetch_discord_user(access_token) or {}
    user_id = str(user_json.get('id') or '').strip()
    if not user_id:
        return redirect('/?auth=failed&reason=user_fetch_failed', code=302)

    avatar_hash = str(user_json.get('avatar') or '').strip()
    if avatar_hash:
        avatar_url = f'https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png?size=256'
    else:
        try:
            avatar_index = int(user_id) % 5
        except ValueError:
            avatar_index = 0
        avatar_url = f'https://cdn.discordapp.com/embed/avatars/{avatar_index}.png'

    ttl_ms = min(int(current_app.config.get('DASHBOARD_SESSION_TTL_MS', _DASHBOARD_SESSION_MAX_TTL_MS)), _DASHBOARD_SESSION_MAX_TTL_MS)
    session_id = secrets.token_hex(32)
    session_data = {
        'expires_at_ms': _unix_ms() + ttl_ms,
        'user': {
            'id': user_id,
            'username': str(user_json.get('username') or 'Unknown'),
            'globalName': str(user_json.get('global_name') or ''),
            'email': str(user_json.get('email') or '').strip().lower(),
            'avatarUrl': avatar_url,
        },
    }
    cookie_token = _build_session_token(session_id, session_data)
    next_path = _safe_next_path(state_row.get('next', '/dashboard'))
    redirect_with_flag = _site_redirect_with_token(next_path, cookie_token, auth_ok=True)
    next_js = json.dumps(redirect_with_flag)

    html = (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in\u2026</title>'
        '<style>*{margin:0;padding:0;box-sizing:border-box}'
        'body{background:#0a0a0b;color:#ccc;display:flex;align-items:center;'
        'justify-content:center;min-height:100vh;font-family:system-ui}'
        '.w{text-align:center}.s{width:42px;height:42px;border:3px solid #222;'
        'border-top-color:#7c3aed;border-radius:50%;animation:sp .8s linear infinite;'
        'margin:0 auto 14px}@keyframes sp{to{transform:rotate(360deg)}}'
        'p{font-size:14px;opacity:.7}</style></head>'
        '<body><div class="w"><div class="s"></div><p>Signing you in\u2026</p></div>'
        '<script>(function(){window.location.replace(' + next_js + ');})();</script></body></html>'
    )
    resp = make_response(html, 200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    # Also set cookie as belt-and-suspenders fallback for browsers that block localStorage.
    _set_dashboard_cookie(resp, cookie_token)
    audit_event('web.oauth.callback.ok', ip=_client_ip())
    return resp


@web_bp.route('/api/auth/activate', methods=['GET'])
def auth_activate():
    raw_token = str(request.args.get('t') or '').strip()
    if not raw_token:
        return jsonify({'ok': False, 'error': 'Missing token'}), 400

    _cleanup_state()
    with _state_lock:
        pending = _pending_auth_tokens.pop(raw_token, None)

    if not pending or int(pending.get('exp', 0)) <= _unix_ms():
        return jsonify({'ok': False, 'error': 'Invalid or expired token. Please log in again.'}), 401

    session_id = str(pending['session_id'])
    session_data = dict(pending['session_data'])

    user = session_data.get('user', {})
    cookie_token = _build_session_token(session_id, session_data)
    response = jsonify({'ok': True, 'user': user, 'token': cookie_token})
    _set_dashboard_cookie(response, cookie_token)
    return response


@web_bp.route('/api/dashboard/logout', methods=['POST'])
def dashboard_logout():
    response = jsonify({'ok': True})
    _clear_dashboard_cookie(response)
    return response, 200


@web_bp.route('/api/dashboard/me', methods=['GET'])
def dashboard_me():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    rows = _licenses_for_user(user)
    active = _choose_summary_license(rows)
    summary = None
    if active is not None and not active.is_revoked and not _is_expired(active):
        plan = _license_plan(active)

        # Check Stripe for cancel_at_period_end so the UI can show "Cancels On" + Renew button
        subscription_canceled = False
        cancel_at_iso = None
        if plan in {'core_monthly', 'pro_monthly'}:
            stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
            customer_id = str((active.extra_metadata or {}).get('stripe_customer', '')).strip()
            if stripe_key and customer_id.startswith('cus_'):
                try:
                    import stripe as _stripe
                    _stripe.api_key = stripe_key
                    subs = _stripe.Subscription.list(customer=customer_id, limit=5, status='all')
                    for sub in (subs.data or []):
                        if sub.status in ('active', 'past_due', 'trialing'):
                            if sub.cancel_at_period_end:
                                subscription_canceled = True
                                if sub.cancel_at:
                                    cancel_at_iso = datetime.fromtimestamp(
                                        int(sub.cancel_at), tz=timezone.utc
                                    ).isoformat()
                            break
                except Exception:
                    pass

        summary = {
            'plan': plan,
            'role': _license_role(active),
            'status': _license_status(active),
            'keyMasked': _mask_key(active.key),
            'keyFull': active.key,
            'hwid': active.hwid_hash or '',
            'expiresAt': _license_expires_iso(active),
            'nextBillingDate': _license_expires_iso(active) if plan in {'core_monthly', 'pro_monthly'} else None,
            'subscriptionCanceled': subscription_canceled,
            'cancelAt': cancel_at_iso,
        }
    return jsonify({'ok': True, 'user': user, 'summary': summary}), 200


@web_bp.route('/api/dashboard/licenses', methods=['GET'])
def dashboard_licenses():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    rows = _licenses_for_user(user)
    items = [{
        'id': row.id,
        'keyMasked': _mask_key(row.key),
        'keyFull': row.key,
        'plan': _license_plan(row),
        'role': _license_role(row),
        'active': (not row.is_revoked),
        'status': _license_status(row),
        'hwid': row.hwid_hash or '',
        'expiresAt': _license_expires_iso(row),
        'createdAt': _license_created_iso(row),
        'note': str((row.extra_metadata or {}).get('notes') or ''),
    } for row in rows]
    return jsonify({'ok': True, 'items': items}), 200


@web_bp.route('/api/dashboard/reset-hwid', methods=['POST'])
def dashboard_reset_hwid():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    if not request.is_json:
        return jsonify({'ok': False, 'error': 'Invalid request'}), 400
    data = request.get_json(silent=True) or {}
    key = str(data.get('key') or '').strip()
    cleaned = ''.join(ch for ch in key if ch.isalnum()).upper()
    if len(cleaned) < 8 or len(cleaned) > 32:
        return jsonify({'ok': False, 'error': 'Invalid key'}), 400

    rows = _licenses_for_user(user)
    target = next((row for row in rows if row.key == cleaned), None)
    if target is None:
        return jsonify({'ok': False, 'error': 'Not allowed for this account'}), 403

    reset_id = f'{user.get("id", "")}:{cleaned}'
    now = _unix_ms()
    with _state_lock:
        last_reset = int(_dashboard_resets.get(reset_id, 0))
    if now - last_reset < (24 * 60 * 60 * 1000):
        return jsonify({'ok': False, 'error': 'Reset cooldown: 24h'}), 429

    target.hwid_hash = None
    target.hwid_change_count = 0
    target.activated_at = None
    target.session_nonce = secrets.token_hex(16)
    db.session.commit()
    with _state_lock:
        _dashboard_resets[reset_id] = now
    audit_event('web.dashboard.reset_hwid.ok', ip=_client_ip(), license_id=target.id)
    return jsonify({'ok': True}), 200


@web_bp.route('/api/dashboard/cancel-subscription', methods=['POST'])
def dashboard_cancel_subscription():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    discord_id = str((user or {}).get('id', '')).strip()

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Not configured'}), 503

    # Find Stripe customer ID from their license metadata
    customer_id = ''
    if discord_id:
        licenses = License.query.filter(
            License._metadata.like(f'%"discord_id": "{discord_id}"%')
        ).all()
        for lic in licenses:
            cid = str((lic.extra_metadata or {}).get('stripe_customer', '')).strip()
            if cid.startswith('cus_'):
                customer_id = cid
                break

    site_url = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key
        if customer_id:
            portal = _stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=f'{site_url}/dashboard',
            )
            return jsonify({'ok': True, 'url': portal.url}), 200
        else:
            # No customer ID on file â€” fall back to static portal URL or support
            fallback = str(current_app.config.get('STRIPE_BILLING_PORTAL_URL', '')).strip()
            if fallback:
                return jsonify({'ok': True, 'url': fallback}), 200
            return jsonify({
                'ok': False,
                'error': 'No billing record found for your account. Contact support.',
            }), 404
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500


@web_bp.route('/api/dashboard/renew-subscription', methods=['POST'])
def dashboard_renew_subscription():
    """Re-activate a subscription that has cancel_at_period_end=True."""
    user, err = _dashboard_user_or_401()
    if err:
        return err
    discord_id = str((user or {}).get('id', '')).strip()

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Not configured'}), 503

    # Find the Stripe customer ID from license metadata
    customer_id = ''
    if discord_id:
        licenses = License.query.filter(
            License._metadata.like(f'%"discord_id": "{discord_id}"%')
        ).all()
        for lic in licenses:
            cid = str((lic.extra_metadata or {}).get('stripe_customer', '')).strip()
            if cid.startswith('cus_'):
                customer_id = cid
                break

    if not customer_id:
        return jsonify({'ok': False, 'error': 'No billing record found for your account. Contact support.'}), 404

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key

        # Find the active subscription that is set to cancel
        subs = _stripe.Subscription.list(customer=customer_id, limit=5, status='all')
        sub_id = None
        for sub in (subs.data or []):
            if sub.status in ('active', 'past_due', 'trialing') and sub.cancel_at_period_end:
                sub_id = sub.id
                break

        if not sub_id:
            return jsonify({'ok': False, 'error': 'No canceled subscription found to renew.'}), 404

        # Re-activate: clear cancel_at_period_end
        _stripe.Subscription.modify(sub_id, cancel_at_period_end=False)
        return jsonify({'ok': True}), 200
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# Individual / Standalone Macros â€” product catalog + entitlements
# ---------------------------------------------------------------------------

@web_bp.route('/api/products', methods=['GET'])
def list_products():
    """Public: list all active standalone products."""
    products = Product.query.filter_by(is_active=True).order_by(Product.sort_order).all()
    items = []
    for product in products:
        item = product.to_dict()
        item.pop('download_ref', None)
        items.append(item)
    return jsonify({'ok': True, 'items': items}), 200


@web_bp.route('/api/standalone/download/<product_id>', methods=['GET'])
def standalone_download(product_id: str):
    """
    Return a direct download URL for a standalone product the user owns.
    Requires dashboard session (Discord OAuth cookie).
    """
    user, err = _dashboard_user_or_401()
    if err:
        return err
    discord_id = str(user.get('id', '')).strip()

    product = Product.query.get(product_id)
    if not product or not product.is_active:
        return jsonify({'ok': False, 'error': 'Unknown product'}), 404
    if not product.download_ref:
        return jsonify({'ok': False, 'error': 'No download available yet'}), 404

    # Check entitlement â€” find all licenses for this discord_id
    licenses = License.query.filter(
        License._metadata.like(f'%"discord_id": "{discord_id}"%')
    ).all()
    key_hashes = [lic.key_hash for lic in licenses if lic.is_active()]

    granted = False
    if key_hashes:
        granted = UserEntitlement.query.filter(
            UserEntitlement.license_key_hash.in_(key_hashes),
            UserEntitlement.product_id == product_id,
        ).first() is not None

    if not granted:
        return jsonify({'ok': False, 'error': 'Not entitled'}), 403

    audit_event('web.standalone.download', product_id=product_id, discord_id=discord_id)

    # Proxy through our backend (repo is private â€” direct GitHub URLs 404 without auth)
    asset_id, filename = _resolve_standalone_asset_id(product.download_ref)
    if asset_id:
        path = _build_download_link(asset_id, filename)
        base = _public_api_root()
        url = f'{base}{path}' if base else path
    else:
        return jsonify({
            'ok': False,
            'error': 'release_asset_missing',
            'message': 'This private download has not been uploaded to the release repository yet.',
        }), 503

    return jsonify({'ok': True, 'url': url}), 200


@web_bp.route('/api/dashboard/entitlements', methods=['GET'])
def dashboard_entitlements():
    """Return the standalone product entitlements for the logged-in user."""
    user, err = _dashboard_user_or_401()
    if err:
        return err
    discord_id = str(user.get('id', '')).strip()
    if not discord_id:
        return jsonify({'ok': True, 'items': []}), 200

    # Find all licenses for this discord_id and collect their entitlements
    licenses = License.query.filter(
        License._metadata.like(f'%"discord_id": "{discord_id}"%')
    ).all()
    key_hashes = [lic.key_hash for lic in licenses if lic.is_active()]

    items = []
    if key_hashes:
        rows = UserEntitlement.query.filter(
            UserEntitlement.license_key_hash.in_(key_hashes)
        ).all()
        items = [
            {'product_id': r.product_id, 'granted_at': r.granted_at.isoformat()}
            for r in rows
        ]
    return jsonify({'ok': True, 'items': items}), 200


@web_bp.route('/api/checkout-standalone', methods=['POST'])
def checkout_standalone():
    """Create a Stripe embedded checkout session for one or more standalone products."""
    user, err = _dashboard_user_or_401()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    # Accept product_ids (array) or product_id (single string, possibly comma-separated)
    raw_ids = data.get('product_ids') or []
    if not raw_ids:
        single = str(data.get('product_id') or '').strip()
        raw_ids = [s.strip() for s in single.split(',') if s.strip()]
    if not raw_ids:
        return jsonify({'ok': False, 'error': 'product_id required'}), 400

    discord_id = str(user.get('id', '')).strip()

    # Validate all products
    products = []
    for pid in raw_ids:
        p = Product.query.get(pid)
        if not p or not p.is_active:
            return jsonify({'ok': False, 'error': f'Product not found: {pid}'}), 404
        if not p.stripe_price_id:
            return jsonify({'ok': False, 'error': f'{p.name} is not yet available for purchase'}), 503
        products.append(p)

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Checkout not configured'}), 503

    # Check if all are already owned
    existing_lic = License.query.filter(
        License._metadata.like(f'%"discord_id": "{discord_id}"%')
    ).first()
    if existing_lic and len(products) == 1:
        already = UserEntitlement.query.filter_by(
            license_key_hash=existing_lic.key_hash,
            product_id=products[0].id,
        ).first()
        if already:
            return jsonify({'ok': False, 'error': 'You already own this product'}), 409

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key
        site = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')
        product_ids_str = ','.join(p.id for p in products)
        meta = {
            'discord_id':       str(user.get('id', '')),
            'discord_username': str(user.get('username', '')),
            'product_ids':      product_ids_str,
            # keep product_id for single-product backward compat
            'product_id':       products[0].id if len(products) == 1 else '',
            'type':             'standalone',
        }
        line_items = [{'price': p.stripe_price_id, 'quantity': 1} for p in products]
        session = _stripe.checkout.Session.create(
            ui_mode='embedded_page',
            mode='payment',
            line_items=line_items,
            return_url=f'{site}/dashboard?payment=success&product={product_ids_str}',
            metadata=meta,
            payment_intent_data={'metadata': {**meta}},
        )
        audit_event('web.checkout.standalone', ip=_client_ip(), product_ids=product_ids_str)
        return jsonify({'ok': True, 'client_secret': session.client_secret}), 200
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Checkout failed: {str(exc)[:200]}'}), 500


def _fulfill_standalone(stripe_ref: str, discord_id: str, product_id: str,
                        charged_cents: int, user_email: str = '') -> None:
    """Grant a standalone product entitlement after successful payment."""
    # Idempotency check
    if UserEntitlement.query.filter_by(stripe_ref=stripe_ref).first():
        return

    product = Product.query.get(product_id)
    if not product:
        audit_event('web.standalone.unknown_product', product_id=product_id, stripe_ref=stripe_ref)
        return

    # Find the user's active license by discord_id
    lic = License.query.filter(
        License._metadata.like(f'%"discord_id": "{discord_id}"%')
    ).filter_by(is_revoked=False).order_by(License.id.desc()).first()

    if not lic:
        # No license found â€” create a standalone-only license for this user.
        normalized = _generate_license_key()
        while License.query.filter_by(key_hash=_sha256_hex(normalized)).first() is not None:
            normalized = _generate_license_key()
        meta = {
            'discord_id': discord_id,
            'plan': 'standalone',
            'stripe_ref': stripe_ref,
            'charged_cents': charged_cents,
        }
        if user_email:
            meta['user_email'] = user_email
        lic = License(
            key=normalized,
            key_hash=_sha256_hex(normalized),
            user_enc_key=secrets.token_hex(32),
            user_salt=secrets.token_hex(16),
            tier='standalone',
            is_revoked=False,
            expires_at=None,
        )
        lic.extra_metadata = meta
        db.session.add(lic)
        db.session.flush()
        audit_event('web.standalone.created_license', discord_id=discord_id,
                    product_id=product_id, license_id=lic.id)

    # Check not already granted
    if UserEntitlement.query.filter_by(
        license_key_hash=lic.key_hash, product_id=product_id
    ).first():
        return

    ent = UserEntitlement(
        license_key_hash=lic.key_hash,
        product_id=product_id,
        stripe_ref=stripe_ref,
        charged_cents=charged_cents,
    )
    db.session.add(ent)

    # If this is a bundle, grant each included product too
    bundle_pids = [x.strip() for x in (product.bundle_items or '').split(',') if x.strip()]
    for bpid in bundle_pids:
        if not UserEntitlement.query.filter_by(
            license_key_hash=lic.key_hash, product_id=bpid
        ).first():
            db.session.add(UserEntitlement(
                license_key_hash=lic.key_hash,
                product_id=bpid,
                stripe_ref=f'{stripe_ref}:bundle:{bpid}',
                charged_cents=0,
            ))

    db.session.commit()
    audit_event('web.standalone.fulfilled', product_id=product_id,
                discord_id=discord_id, license_id=lic.id)

    # Grant Individual Macros Discord role (DISCORD_STANDALONE_ROLE_ID)
    grant_standalone_role(discord_id, current_app.config)

    # Sale notification â€” reuse shared helper
    _post_sale_notification(
        discord_id=discord_id,
        plan=f'standalone:{product.name}',
        charged_cents=charged_cents,
        license_key=lic.key if hasattr(lic, 'key') else '',
        user_email=user_email,
        stripe_ref=stripe_ref,
        product_name=product.name,
    )
    _send_purchase_dm(discord_id, f'standalone:{product.name}', product_name=product.name)


## Old /api/pricing removed â€” superseded by pricing_info() below with full plan metadata


@web_bp.route('/api/create-checkout', methods=['GET'])
def create_checkout():
    user, err = _dashboard_user_or_401()
    if err:
        next_url = quote('/api/create-checkout?' + request.query_string.decode('utf-8', errors='ignore'), safe='')
        return redirect(f'/auth/discord/start?next={next_url}', code=302)

    plan = _normalize_checkout_plan(request.args.get('plan') or 'core_monthly')

    ref = str(request.args.get('ref') or '').strip()[:64]

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Checkout is not configured yet'}), 503

    if plan == 'core_monthly':
        price_id = str(current_app.config.get('STRIPE_PRICE_CORE_MONTHLY', '') or current_app.config.get('STRIPE_PRICE_MONTHLY', '')).strip()
        mode = 'subscription'
    elif plan == 'pro_monthly':
        price_id = str(current_app.config.get('STRIPE_PRICE_PRO_MONTHLY', '') or current_app.config.get('STRIPE_PRICE_3MONTH', '')).strip()
        mode = 'subscription'
    elif plan == 'core_lifetime':
        price_id = str(current_app.config.get('STRIPE_PRICE_LIFETIME_CORE', '') or current_app.config.get('STRIPE_PRICE_LIFETIME', '')).strip()
        mode = 'payment'
    else:
        price_id = str(current_app.config.get('STRIPE_PRICE_LIFETIME_PRO', '') or current_app.config.get('STRIPE_PRICE_LIFETIME', '')).strip()
        mode = 'payment'

    if not price_id:
        return jsonify({'ok': False, 'error': 'Checkout is not configured yet'}), 503

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key
        site = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')
        meta = {
            'discord_id': str(user.get('id', '')),
            'discord_username': str(user.get('username', '')),
            'plan': plan,
        }
        if ref:
            meta['affiliate_code'] = ref
        session = _stripe.checkout.Session.create(
            mode=mode,
            line_items=[{'price': price_id, 'quantity': 1}],
            success_url=f'{site}/dashboard?payment=success',
            cancel_url=f'{site}/#pricing',
            allow_promotion_codes=True,
            metadata=meta,
            **(
                {'subscription_data': {'metadata': {**meta}}}
                if mode == 'subscription' else
                {'payment_intent_data': {'metadata': {**meta}}}
            ),
        )
        audit_event('web.checkout.redirect', ip=_client_ip(), plan=plan)
        return redirect(session.url, code=302)
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Checkout failed: {str(exc)[:200]}'}), 500


@web_bp.route('/api/stripe-config', methods=['GET'])
def stripe_config():
    pk = str(current_app.config.get('STRIPE_PUBLISHABLE_KEY', '')).strip()
    if not pk:
        return jsonify({'ok': False, 'error': 'Not configured'}), 404
    return jsonify({'ok': True, 'publishable_key': pk}), 200


@web_bp.route('/api/pricing', methods=['GET'])
def pricing_info():
    """Single source of truth for plan pricing, served to the frontend."""
    monthly_value = float(current_app.config.get('MONTHLY_PRICE_DISPLAY', 6.99) or 6.99)
    pro_monthly_value = float(current_app.config.get('PRO_MONTHLY_PRICE_DISPLAY', 19.99) or 19.99)
    lifetime_core_value = float(current_app.config.get('LIFETIME_CORE_PRICE_DISPLAY', 12.99) or 12.99)
    lifetime_pro_value = float(current_app.config.get('LIFETIME_PRO_PRICE_DISPLAY', 34.99) or 34.99)
    lifetime_core_currency = str(current_app.config.get('LIFETIME_CORE_CURRENCY', 'USD') or 'USD').upper()
    plans = {
        'core_monthly': {
            'name': 'Core Monthly',
            'desc': 'Core Divine access with monthly billing.',
            'price': f'${monthly_value:.2f}'.rstrip('0').rstrip('.'),
            'amount': int(round(monthly_value * 100)),
            'period': '/mo',
            'currency': 'USD',
        },
        'pro_monthly': {
            'name': 'Pro Monthly',
            'desc': 'All Pro features, including Divine Community, billed every 30 days.',
            'price': f'${pro_monthly_value:.2f}'.rstrip('0').rstrip('.'),
            'amount': int(round(pro_monthly_value * 100)),
            'period': '/mo',
            'currency': 'USD',
        },
        'core_lifetime': {
            'name': 'Core Lifetime',
            'desc': 'Permanent access with the core lifetime package.',
            'price': f'${lifetime_core_value:.2f}'.rstrip('0').rstrip('.'),
            'amount': int(round(lifetime_core_value * 100)),
            'period': 'one-time',
            'currency': 'USD',
        },
        'pro_lifetime': {
            'name': 'Pro Lifetime',
            'desc': 'Permanent access with the full pro lifetime package.',
            'price': f'${lifetime_pro_value:.2f}'.rstrip('0').rstrip('.'),
            'amount': int(round(lifetime_pro_value * 100)),
            'period': 'one-time',
            'currency': 'USD',
        },
    }
    plans['monthly'] = dict(plans['core_monthly'])
    plans['3month'] = dict(plans['pro_monthly'])
    plans['lifetime_core'] = dict(plans['core_lifetime'])
    plans['lifetime_pro'] = dict(plans['pro_lifetime'])
    plans['lifetime'] = dict(plans['pro_lifetime'])
    portal_url = str(current_app.config.get('STRIPE_BILLING_PORTAL_URL', '')).strip() or None
    return jsonify({'ok': True, 'plans': plans, 'portal_url': portal_url}), 200


@web_bp.route('/api/checkout-session', methods=['POST'])
def checkout_session():
    user, err = _dashboard_user_or_401()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    plan = _normalize_checkout_plan(data.get('plan') or 'core_monthly')

    ref      = str(data.get('ref') or '').strip()[:64]
    promo_id = str(data.get('promo_id') or '').strip()[:128]

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Checkout is not configured'}), 503

    if plan == 'core_monthly':
        price_id = str(current_app.config.get('STRIPE_PRICE_CORE_MONTHLY', '') or current_app.config.get('STRIPE_PRICE_MONTHLY', '')).strip()
        mode = 'subscription'
    elif plan == 'pro_monthly':
        price_id = str(current_app.config.get('STRIPE_PRICE_PRO_MONTHLY', '') or current_app.config.get('STRIPE_PRICE_3MONTH', '')).strip()
        mode = 'subscription'
    elif plan == 'core_lifetime':
        price_id = str(current_app.config.get('STRIPE_PRICE_LIFETIME_CORE', '') or current_app.config.get('STRIPE_PRICE_LIFETIME', '')).strip()
        mode = 'payment'
    else:
        price_id = str(current_app.config.get('STRIPE_PRICE_LIFETIME_PRO', '') or current_app.config.get('STRIPE_PRICE_LIFETIME', '')).strip()
        mode = 'payment'

    if not price_id:
        return jsonify({'ok': False, 'error': 'Checkout is not configured'}), 503

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key
        site = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')
        meta = {
            'discord_id': str(user.get('id', '')),
            'discord_username': str(user.get('username', '')),
            'plan': plan,
        }
        if ref:
            meta['affiliate_code'] = ref
        if promo_id:
            meta['stripe_promo_id'] = promo_id

        extra = {}
        if promo_id:
            extra['discounts'] = [{'promotion_code': promo_id}]
        else:
            extra['allow_promotion_codes'] = True

        session = _stripe.checkout.Session.create(
            ui_mode='embedded_page',
            mode=mode,
            line_items=[{'price': price_id, 'quantity': 1}],
            return_url=f'{site}/dashboard?payment=success&session_id={{CHECKOUT_SESSION_ID}}',
            metadata=meta,
            **(
                {'subscription_data': {'metadata': {**meta}}}
                if mode == 'subscription' else
                {'payment_intent_data': {'metadata': {**meta}}}
            ),
            **extra,
        )
        audit_event('web.checkout.embedded', ip=_client_ip(), plan=plan)
        return jsonify({'ok': True, 'client_secret': session.client_secret}), 200
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Checkout failed: {str(exc)[:200]}'}), 500


@web_bp.route('/api/validate-code', methods=['POST'])
def validate_code():
    data = request.get_json(silent=True) or {}
    code      = str(data.get('code') or '').strip()
    code_type = str(data.get('type') or '').lower()

    if not code:
        return jsonify({'ok': False, 'error': 'No code provided'}), 400

    if code_type == 'referral':
        found = False
        owner_discord_id = None
        try:
            # Use indexed affiliate_code column for O(1) lookup
            lic = License.query.filter(License.affiliate_code == code.lower()).first()
            if lic:
                found = True
                owner_discord_id = str((lic.extra_metadata or {}).get('discord_id', '')).strip()
        except Exception:
            pass
        if found:
            # Block the affiliate owner from using their own code
            try:
                _sess_sid, sess = _dashboard_session()
            except Exception:
                sess = None
            if sess and owner_discord_id and str(sess.get('discord_id', '')).strip() == owner_discord_id:
                return jsonify({'ok': False, 'error': "You can't use your own referral code."}), 200
            return jsonify({'ok': True, 'type': 'referral', 'code': code.lower()}), 200
        return jsonify({'ok': False, 'error': 'Referral code not found'}), 200

    if code_type == 'coupon':
        stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
        if not stripe_key:
            return jsonify({'ok': False, 'error': 'Not configured'}), 503
        try:
            import stripe as _stripe
            _stripe.api_key = stripe_key
            promos = _stripe.PromotionCode.list(code=code, active=True, limit=1)
            if not promos.data:
                return jsonify({'ok': False, 'error': 'Coupon not found or expired'}), 200
            promo  = promos.data[0]
            # stripe-python v3+: .coupon attribute moved to .promotion.coupon (an ID)
            try:
                coupon = promo.coupon
            except AttributeError:
                promo_dict = promo.to_dict() if hasattr(promo, 'to_dict') else {}
                coupon_id = (promo_dict.get('promotion') or {}).get('coupon') or ''
                coupon = _stripe.Coupon.retrieve(coupon_id) if coupon_id else None
            if coupon and getattr(coupon, 'percent_off', None):
                disc = {'type': 'percent', 'percent': float(coupon.percent_off)}
            elif coupon and getattr(coupon, 'amount_off', None):
                disc = {'type': 'amount', 'amount_off': int(coupon.amount_off), 'currency': getattr(coupon, 'currency', 'usd')}
            else:
                disc = {}
            return jsonify({'ok': True, 'type': 'stripe_coupon', 'code': code, 'promo_id': promo.id, 'discount': disc}), 200
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)[:200]}), 500

    return jsonify({'ok': False, 'error': 'Invalid type'}), 400


@web_bp.route('/api/payment-intent', methods=['POST'])
def create_payment_intent():
    user, err = _dashboard_user_or_401()
    if err:
        return err

    data      = request.get_json(silent=True) or {}
    plan      = _normalize_checkout_plan(data.get('plan') or 'lifetime_pro')
    ref       = str(data.get('ref') or '').strip()[:64]
    promo_id  = str(data.get('promo_id') or '').strip()[:128]

    if plan not in {'core_lifetime', 'pro_lifetime'}:
        return jsonify({'ok': False, 'error': 'Use /api/create-checkout for monthly'}), 400

    stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
    if not stripe_key:
        return jsonify({'ok': False, 'error': 'Not configured'}), 503

    discord_id = str(user.get('id', ''))
    username   = str(user.get('username', ''))
    meta = {'discord_id': discord_id, 'discord_username': username, 'plan': plan}
    if ref:
        meta['referral_code'] = ref
    if promo_id:
        meta['stripe_promo_id'] = promo_id

    try:
        import stripe as _stripe
        _stripe.api_key = stripe_key
        amount = 1299 if plan == 'core_lifetime' else 1999

        # Apply Stripe promo discount to the PaymentIntent amount
        if promo_id:
            try:
                promo  = _stripe.PromotionCode.retrieve(promo_id)
                coupon = promo.coupon
                if coupon.percent_off:
                    amount = max(50, int(amount * (1 - coupon.percent_off / 100)))
                elif coupon.amount_off:
                    amount = max(50, amount - int(coupon.amount_off))
            except Exception:
                pass

        pi = _stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            metadata=meta,
        )
        audit_event('web.payment_intent.lifetime', ip=_client_ip(), plan=plan)
        return jsonify({'ok': True, 'client_secret': pi.client_secret, 'type': 'payment_intent', 'amount': amount}), 200

    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Failed: {str(exc)[:200]}'}), 500


@web_bp.route('/api/resend-license-email', methods=['POST'])
def resend_license_email():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    _ = user
    return jsonify({
        'ok': False,
        'error': 'License resend is not configured in this migration baseline yet.',
    }), 501


@web_bp.route('/api/releases', methods=['GET'])
def releases():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    if not _active_full_client_license(user):
        return jsonify({'ok': False, 'error': 'subscription_required'}), 403

    if not _github_release_ready():
        return jsonify({'ok': False, 'note': 'no_repo_configured'}), 200

    repo = _release_repo()
    req = _github_api_request(f'https://api.github.com/repos/{repo}/releases?per_page=8')
    try:
        payload = _json_from_url(req)
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not load releases'}), 503

    if not isinstance(payload, list):
        return jsonify({'ok': False, 'error': 'Invalid release response'}), 503

    releases_payload = []
    for rel in payload:
        rel_assets = rel.get('assets') or []
        assets_out = []
        for asset in rel_assets:
            asset_id = int(asset.get('id') or 0)
            asset_name = str(asset.get('name') or '').strip()
            if not asset_id or not asset_name:
                continue
            assets_out.append({
                'name': asset_name,
                'size': int(asset.get('size') or 0),
                'url': _build_download_link(asset_id, asset_name),
            })
        releases_payload.append({
            'tag': str(rel.get('tag_name') or '').strip(),
            'name': str(rel.get('name') or '').strip(),
            'draft': bool(rel.get('draft')),
            'prerelease': bool(rel.get('prerelease')),
            'published_at': str(rel.get('published_at') or '').strip(),
            'body': str(rel.get('body') or ''),
            'assets': assets_out,
        })

    return jsonify({'ok': True, 'releases': releases_payload}), 200


@web_bp.route('/api/dashboard/download-latest', methods=['GET'])
def dashboard_download_latest():
    user, err = _dashboard_user_or_401()
    if err:
        return err

    if not _active_full_client_license(user):
        return jsonify({
            'ok': False,
            'error': 'subscription_required',
            'message': 'An active Divine subscription is required to download the client.',
        }), 403

    release = _latest_release_data(direct_exe_only=True)
    if not release:
        return jsonify({'ok': False, 'error': 'Latest release is not configured yet'}), 503

    path = _build_download_link(int(release['assetId']), str(release['assetName']))
    url = f'{_public_api_root()}{path}'
    return jsonify({
        'ok': True,
        'version': release['version'],
        'releaseName': release.get('releaseName', ''),
        'releaseNotes': release.get('releaseNotes', ''),
        'publishedAt': release['publishedAt'],
        'assetName': release['assetName'],
        'size': release['assetSize'],
        'url': url,
    }), 200


@web_bp.route('/api/dashboard/installer-command', methods=['GET'])
def dashboard_installer_command():
    user, err = _dashboard_user_or_401()
    if err:
        return err

    active = _active_full_client_license(user)
    if not active:
        return jsonify({
            'ok': False,
            'error': 'subscription_required',
            'message': 'A Divine subscription is required to use secure install.',
        }), 403
    if not _secure_install_allowed(active):
        return jsonify({
            'ok': False,
            'error': 'pro_required',
            'message': 'Secure install is available for Pro Monthly and Pro Lifetime plans only.',
        }), 403

    release = _latest_release_data()
    if not release:
        return jsonify({'ok': False, 'error': 'Latest release is not configured yet'}), 503

    sha256_hex = _latest_release_sha256(release)
    if not sha256_hex:
        return jsonify({'ok': False, 'error': 'Could not prepare integrity verification'}), 503

    token = _build_download_token(
        int(release['assetId']),
        str(release['assetName']),
        extra={
            'discord_id': str(user.get('id') or '')[:64],
            'purpose': 'secure_install',
        },
    )
    base_url = request.url_root.rstrip('/')
    download_url = f'{base_url}/api/client/download?token={quote(token, safe="")}'
    command = _build_secure_install_command(download_url, sha256_hex, str(release['assetName']))
    audit_event(
        'web.dashboard.installer_command',
        ip=_client_ip(),
        discord_id=str(user.get('id') or '')[:64],
        plan=_license_plan(active),
        asset_name=str(release['assetName'])[:96],
    )
    return jsonify({
        'ok': True,
        'plan': _license_plan(active),
        'version': release['version'],
        'assetName': release['assetName'],
        'sha256': sha256_hex,
        'expiresInSec': max(60, int(current_app.config.get('DOWNLOAD_URL_TTL_SECONDS', 900))),
        'downloadUrl': download_url,
        'command': command,
    }), 200


@web_bp.route('/api/dashboard/launch-command', methods=['GET'])
def dashboard_launch_command():
    user, err = _dashboard_user_or_401()
    if err:
        return err

    active = _active_full_client_license(user)
    if not active:
        return jsonify({
            'ok': False,
            'error': 'subscription_required',
            'message': 'A Divine subscription is required to launch the full client.',
        }), 403

    release = _latest_release_data(direct_exe_only=True)
    if not release:
        return jsonify({'ok': False, 'error': 'Latest release is not configured yet'}), 503

    asset_name = str(release.get('assetName') or '').strip()
    if not _is_direct_client_asset_name(asset_name):
        return jsonify({
            'ok': False,
            'error': 'launch_requires_exe',
            'message': 'Temporary launch needs a real Divine Macros .exe release asset, not an installer.',
        }), 503

    sha256_hex_value = _latest_release_sha256(release)
    if not sha256_hex_value:
        return jsonify({'ok': False, 'error': 'Could not prepare integrity verification'}), 503

    download_token = _build_download_token(
        int(release['assetId']),
        asset_name,
        extra={
            'discord_id': str(user.get('id') or '')[:64],
            'purpose': 'temporary_launch',
        },
    )
    launch_token = _build_launch_token(active, str(user.get('id') or ''))
    download_url = f'{_public_api_root()}/api/client/download?token={quote(download_token, safe="")}'
    command = _build_temporary_launch_command(
        download_url,
        sha256_hex_value,
        asset_name,
        launch_token,
        str(active.key or '')[:4],
    )
    audit_event(
        'web.dashboard.launch_command',
        ip=_client_ip(),
        discord_id=str(user.get('id') or '')[:64],
        plan=_license_plan(active),
        asset_name=asset_name[:96],
    )
    return jsonify({
        'ok': True,
        'plan': _license_plan(active),
        'version': release['version'],
        'assetName': asset_name,
        'sha256': sha256_hex_value,
        'expiresInSec': _launch_command_ttl_seconds(),
        'downloadUrl': download_url,
        'command': command,
    }), 200


@web_bp.route('/api/bot/download-link', methods=['GET'])
def bot_download_link():
    if not _bot_api_authorized():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    discord_id = request.args.get('discord_id', '').strip()
    if not discord_id:
        return jsonify({'ok': False, 'error': 'discord_id_required'}), 400

    active = _active_full_client_license({'id': discord_id})
    if not active:
        return jsonify({'ok': False, 'error': 'subscription_required'}), 403

    release = _latest_release_data()
    if not release:
        return jsonify({'ok': False, 'error': 'Latest release is not configured yet'}), 503

    path = _build_download_link(int(release['assetId']), str(release['assetName']))
    url = f'{_public_api_root()}{path}'
    return jsonify({
        'ok': True,
        'version': release['version'],
        'assetName': release['assetName'],
        'url': url,
    }), 200


@web_bp.route('/api/client/download', methods=['GET'])
def client_download():
    token = str(request.args.get('token') or '').strip()
    payload = _unpack_signed_json(token)
    if not payload:
        return jsonify({'ok': False, 'error': 'Invalid download token'}), 401

    exp = int(payload.get('exp') or 0)
    asset_id = int(payload.get('asset_id') or 0)
    asset_name = str(payload.get('asset_name') or '').strip()
    if exp <= _unix_ms() or asset_id <= 0 or not asset_name:
        return jsonify({'ok': False, 'error': 'Download token expired'}), 401

    try:
        audit_event(
            'web.client.download',
            ip=_client_ip(),
            discord_id=str(payload.get('discord_id') or '')[:64],
            purpose=str(payload.get('purpose') or 'download')[:48],
            asset_name=asset_name[:96],
        )
    except Exception:
        pass

    repo = _release_repo()
    if not repo:
        return jsonify({'ok': False, 'error': 'Release repository is not configured'}), 503

    release = _latest_release_data() or {}
    bytes_out = _fetch_release_asset_bytes(
        asset_id,
        str(release.get('browserDownloadUrl') or '').strip(),
    )
    if not bytes_out:
        return jsonify({'ok': False, 'error': 'Could not fetch release asset'}), 503

    response = make_response(bytes_out)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{asset_name}"'
    response.headers['Cache-Control'] = 'no-store'
    return response


@web_bp.route('/api/client/redeem-launch', methods=['POST'])
def client_redeem_launch():
    if not _rate_limit('redeem_launch', 45):
        return jsonify({'ok': False, 'error': 'Too many requests'}), 429
    if not request.is_json:
        return jsonify({'ok': False, 'error': 'Invalid request'}), 400

    body = request.get_json(silent=True) or {}
    token = str(body.get('token') or '').strip()
    hwid_fp = str(body.get('hwid_fp') or '').strip().lower()
    if not token or len(token) > 4096 or len(hwid_fp) != 64 or any(ch not in '0123456789abcdef' for ch in hwid_fp):
        return jsonify({'ok': False, 'error': 'Invalid request'}), 400

    payload = _unpack_signed_json(token)
    if not payload:
        return jsonify({'ok': False, 'error': 'Invalid launch token'}), 401
    if str(payload.get('typ') or '') != 'divine_launch' or int(payload.get('v') or 0) != 1:
        return jsonify({'ok': False, 'error': 'Invalid launch token'}), 401
    if int(payload.get('exp') or 0) <= _unix_ms():
        return jsonify({'ok': False, 'error': 'Launch token expired'}), 401

    try:
        license_id = int(payload.get('lid') or 0)
    except Exception:
        license_id = 0
    if license_id <= 0:
        return jsonify({'ok': False, 'error': 'Invalid launch token'}), 401

    license_row = db.session.get(License, license_id)
    if license_row is None or not license_row.is_active() or license_row.tier == 'standalone':
        return jsonify({'ok': False, 'error': 'License unavailable'}), 403

    expected_discord_id = str((license_row.extra_metadata or {}).get('discord_id') or '').strip()
    token_discord_id = str(payload.get('uid') or '').strip()
    if expected_discord_id and token_discord_id and expected_discord_id != token_discord_id:
        return jsonify({'ok': False, 'error': 'Launch token rejected'}), 403

    new_hwid_hash = sha256_hex(hwid_fp)
    max_changes = int(current_app.config.get('MAX_HWID_CHANGES', 3) or 3)
    if license_row.hwid_hash is None:
        license_row.hwid_hash = new_hwid_hash
        license_row.activated_at = _utc_now()
    elif not hmac.compare_digest(str(license_row.hwid_hash or ''), new_hwid_hash):
        if int(license_row.hwid_change_count or 0) >= max_changes:
            return jsonify({'ok': False, 'error': 'HWID locked'}), 401
        license_row.hwid_hash = new_hwid_hash
        license_row.hwid_change_count = int(license_row.hwid_change_count or 0) + 1

    license_row.session_nonce = secrets.token_hex(16)
    license_row.last_validated = _utc_now()
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Internal error'}), 500

    session_data = get_session_manager().create_session(license_row, hwid_fp)
    audit_event(
        'web.client.redeem_launch',
        ip=_client_ip(),
        license_id=license_row.id,
        discord_id=token_discord_id[:64],
        plan=_license_plan(license_row),
    )
    return jsonify({
        **session_data,
        'key': str(license_row.key or ''),
        'hwid_fp': hwid_fp,
    }), 200


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# EXE Builder helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Preset disguise icon colours (solid rounded-rect, generated by Pillow)
_ICON_PRESETS: dict[str, dict] = {
    'spotify': {'bg': (30, 215, 96),   'fg': (255, 255, 255), 'logo_file': 'spotify.png'},
    'discord': {'bg': (88, 101, 242),  'fg': (255, 255, 255), 'logo_file': 'discord.webp'},
    'chrome':  {'bg': (255, 255, 255), 'fg': (66, 133, 244),  'logo_file': 'chrome.png'},
    'steam':   {'bg': (27, 40, 56),    'fg': (199, 213, 224), 'logo_file': 'steam.png'},
    'obs':     {'bg': (50, 50, 50),    'fg': (255, 255, 255), 'logo_file': 'obs.png'},
}

import struct as _struct
import io as _io

# In-memory cache for logo bytes: key â†’ bytes
_logo_fetch_cache: dict[str, bytes] = {}

import os as _os

def _fetch_logo_png(logo_file: str) -> bytes | None:
    """Fetch a brand logo, trying local filesystem first then the live website CDN."""
    if not logo_file:
        return None
    cached = _logo_fetch_cache.get(logo_file)
    if cached is not None:
        return cached

    data: bytes | None = None

    # 1. Try local filesystem (works in dev and when Docker COPY lands correctly)
    try:
        this = _os.path.dirname(__file__)
        for up in (1, 2, 3):
            p = _os.path.normpath(_os.path.join(this, *(['..'] * up), 'logos', logo_file))
            if _os.path.exists(p):
                with open(p, 'rb') as fh:
                    data = fh.read()
                break
            p2 = _os.path.normpath(_os.path.join(this, *(['..'] * up), 'website', 'public', 'logos', logo_file))
            if _os.path.exists(p2):
                with open(p2, 'rb') as fh:
                    data = fh.read()
                break
    except Exception:
        pass

    # 2. Fall back to fetching from the live website (always works on Fly.io)
    if not data:
        try:
            from urllib.request import Request as _Req, urlopen as _urlopen
            site = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')
            url = f'{site}/logos/{logo_file}'
            req = _Req(url, headers={'User-Agent': 'divinemacros-icon-gen/1.0'})
            with _urlopen(req, timeout=8) as resp:
                data = resp.read()
        except Exception:
            pass

    if data:
        _logo_fetch_cache[logo_file] = data
    return data or None


def _make_icon_pil(bg: tuple[int, int, int], size: int, logo_file: str = ''):
    """Return a PIL RGBA Image: transparent background with centred logo (no coloured rect)."""
    try:
        from PIL import Image
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        if logo_file:
            logo_bytes = _fetch_logo_png(logo_file)
            if logo_bytes:
                try:
                    logo = Image.open(_io.BytesIO(logo_bytes)).convert('RGBA')
                    max_dim = int(size * 0.95)
                    logo.thumbnail((max_dim, max_dim), Image.LANCZOS)
                    ox = (size - logo.width) // 2
                    oy = (size - logo.height) // 2
                    img.paste(logo, (ox, oy), logo)
                except Exception:
                    pass
        return img
    except Exception:
        return None


def _make_bmp_icon_data(bg: tuple[int, int, int], size: int, logo_file: str = '') -> bytes:
    """Generate a BMP RT_ICON resource (BITMAPINFOHEADER + BGRA pixels + AND mask)."""
    r, g, b = bg
    try:
        pil_img = _make_icon_pil(bg, size, logo_file)
        if pil_img is not None:
            pil_img = pil_img.convert('RGBA')
            pixels = list(pil_img.getdata())
            # BMP pixel data is stored bottom-up
            rows_bgra = []
            for row_i in range(size - 1, -1, -1):
                for col_i in range(size):
                    px = pixels[row_i * size + col_i]
                    rows_bgra.extend([px[2], px[1], px[0], px[3]])  # BGRA
            xor_mask = bytes(rows_bgra)
        else:
            row = bytes([b, g, r, 255]) * size
            xor_mask = row * size
    except Exception:
        row = bytes([b, g, r, 255]) * size
        xor_mask = row * size

    header = _struct.pack(
        '<IIIHHIIIIII',
        40, size, size * 2, 1, 32, 0,
        size * size * 4, 0, 0, 0, 0,
    )
    row_stride = (size + 31) // 32 * 4
    and_mask = b'\x00' * (row_stride * size)
    return header + xor_mask + and_mask


def _make_png_for_slot(bg: tuple[int, int, int], size: int, logo_file: str, max_bytes: int) -> bytes:
    """Return a 32-bit RGBA PNG of exactly `size`Ã—`size` px that fits within `max_bytes`.

    Windows icon PNG slots require exactly 32-bit RGBA PNGs.

    Strategy (applied in order until a result fits):
    1. Full-quality RGBA with rounded-rect transparency.
    2. Quantised to progressively fewer unique colours, *flattened onto the solid
       brand background* so all pixels are fully opaque.  Removing the alpha
       channel's anti-aliased corner data is the key: those ~thousands of unique
       alpha values prevent DEFLATE from compressing large PNGs below slot size.
       A 256Ã—256 RGBA image with only 8 unique opaque RGBA tuples compresses to
       â‰ˆ100-500 bytes â€” well within any slot.
    3. Tiny solid-colour RGBA PNG as absolute last resort (slot too small even
       for a flat 8Ã—8 image with the logo).
    """
    try:
        from PIL import Image, ImageDraw

        img = _make_icon_pil(bg, size, logo_file)
        if img is None:
            img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            ImageDraw.Draw(img).rounded_rectangle(
                [0, 0, size - 1, size - 1], radius=max(4, size // 7), fill=(*bg, 255)
            )

        # â”€â”€ 1. Full-quality RGBA (includes transparent rounded corners) â”€â”€
        buf = _io.BytesIO()
        img.save(buf, format='PNG', optimize=True, compress_level=9)
        data = buf.getvalue()
        if data and len(data) <= max_bytes:
            return data

        # â”€â”€ 2. Binary alpha + progressively fewer RGB colours â”€â”€
        # Thresholding alpha to 0/255 removes anti-aliased edge entropy, which is
        # the main reason transparent PNGs don't compress small enough for tight slots.
        # Then quantising the RGB channels further shrinks DEFLATE output while keeping
        # colour type 6 (32-bit RGBA) as required by Windows.
        a_ch = img.split()[3]
        a_binary = a_ch.point(lambda x: 255 if x > 128 else 0)
        rgb = Image.merge('RGB', img.split()[:3])

        for n_colors in (128, 64, 32, 16, 8, 4, 2):
            try:
                q_rgb = rgb.quantize(colors=n_colors,
                                     method=Image.Quantize.FASTOCTREE).convert('RGB')
                q_rgba = q_rgb.convert('RGBA')
                q_rgba.putalpha(a_binary)  # restore binary transparency
                buf = _io.BytesIO()
                q_rgba.save(buf, format='PNG', optimize=True, compress_level=9)
                data = buf.getvalue()
                if data and len(data) <= max_bytes:
                    return data
            except Exception:
                continue

        # â”€â”€ 3. Absolute last resort: tiny solid-colour square â”€â”€
        r, g, b = bg
        for tiny in (8, 4, 2, 1):
            tiny_img = Image.new('RGBA', (tiny, tiny), (r, g, b, 255))
            buf = _io.BytesIO()
            tiny_img.save(buf, format='PNG', optimize=True, compress_level=9)
            data = buf.getvalue()
            if data and len(data) <= max_bytes:
                return data

        return b''
    except Exception:
        return b''


def _patch_version_block(block: bytearray, strings: dict[str, str]) -> None:
    """Patch keyâ†’value pairs inside a VS_VERSION_INFO binary blob (in-place).

    Keys and values are stored as null-terminated UTF-16LE strings.  We search
    for each key, then overwrite the value that follows it in-place.  If the
    new value is shorter we zero-pad the remainder.  If it is longer we
    truncate to fit so we never change the resource block size (which would
    corrupt the PE).
    """
    for key, new_val in strings.items():
        key_utf16 = key.encode('utf-16-le') + b'\x00\x00'
        search_buf = bytes(block)
        pos = search_buf.find(key_utf16)
        if pos == -1:
            continue

        # Value starts after the key, aligned to a 4-byte boundary
        val_start = pos + len(key_utf16)
        rem = val_start % 4
        if rem:
            val_start += 4 - rem

        if val_start >= len(block):
            continue

        # Find end of existing value (UTF-16LE null terminator \x00\x00)
        val_end = val_start
        while val_end + 1 < len(block):
            if block[val_end] == 0 and block[val_end + 1] == 0:
                val_end += 2
                break
            val_end += 2

        existing_space = val_end - val_start
        if existing_space < 2:
            continue

        new_utf16 = new_val.encode('utf-16-le') + b'\x00\x00'
        if len(new_utf16) <= existing_space:
            block[val_start:val_start + len(new_utf16)] = new_utf16
            block[val_start + len(new_utf16):val_end] = b'\x00' * (existing_space - len(new_utf16))
        else:
            # Truncate â€” keep as many characters as fit, always keep null terminator
            max_chars = (existing_space // 2) - 1
            truncated = new_val[:max_chars].encode('utf-16-le') + b'\x00\x00'
            block[val_start:val_end] = truncated[:existing_space]


def _patch_exe_version_strings(exe_bytes: bytes, strings: dict[str, str]) -> bytes:
    """Locate the RT_VERSION resource in a PE file and patch string fields inside it."""
    try:
        import pefile as _pefile  # lazy import â€” may not be installed in dev
        pe = _pefile.PE(data=exe_bytes, fast_load=True)
        pe.parse_data_directories(directories=[
            _pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ])
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return exe_bytes

        result = bytearray(exe_bytes)
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.id != _pefile.RESOURCE_TYPE['RT_VERSION']:
                continue
            for res_id in res_type.directory.entries:
                for res_lang in res_id.directory.entries:
                    rva = res_lang.data.struct.OffsetToData
                    size = res_lang.data.struct.Size
                    offset = pe.get_offset_from_rva(rva)
                    block = bytearray(exe_bytes[offset:offset + size])
                    _patch_version_block(block, strings)
                    result[offset:offset + size] = block
                    return bytes(result)  # Only one RT_VERSION per EXE

        return bytes(result)
    except Exception:
        return exe_bytes


def _sanitize_pe_binary(exe_bytes: bytes, preset: str, version_str: str = '1.0.0.0') -> bytes:
    """Strip and replace PE metadata that fingerprints the binary origin.

    Safe operations only â€” code sections (.text etc.) are never modified:
      1. Zero the Rich header  (compiler/linker stamp)
      2. Strip the debug data-directory entry  (removes PDB pointer)
      3. Overwrite CodeView RSDS PDB path strings
      4. Replace RT_MANIFEST with a clean preset-appropriate XML
      5. Recalculate the PE optional-header checksum
    """
    _DISPLAY = {
        'spotify': 'Spotify', 'discord': 'Discord',
        'chrome': 'Google Chrome', 'steam': 'Steam', 'obs': 'OBS Studio',
    }
    _ARCH = {
        'spotify': 'Spotify', 'discord': 'Discord',
        'chrome': 'GoogleChrome', 'steam': 'Steam', 'obs': 'OBSStudio',
    }
    display  = _DISPLAY.get(preset, 'Spotify')
    arch_name = _ARCH.get(preset, 'Spotify')

    # Ensure version is in W.X.Y.Z form for the manifest assemblyIdentity
    parts = (version_str or '1.0.0.0').split('.')
    while len(parts) < 4:
        parts.append('0')
    manifest_ver = '.'.join(parts[:4])

    try:
        import pefile as _pefile

        result = bytearray(exe_bytes)

        # â”€â”€ 1. Zero Rich header (compiler/linker fingerprint) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            pe_off = _struct.unpack_from('<I', exe_bytes, 0x3C)[0]
            if 0x80 < pe_off < len(exe_bytes):
                area = exe_bytes[0x80:pe_off]
                rp = area.rfind(b'Rich')
                if rp != -1:
                    end = 0x80 + rp + 8   # "Rich" (4) + XOR key (4)
                    result[0x80:end] = b'\x00' * (end - 0x80)
        except Exception:
            pass

        pe = _pefile.PE(data=exe_bytes, fast_load=True)
        pe.parse_data_directories(directories=[
            _pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            _pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        ])

        # â”€â”€ 2. Zero debug data-directory entry (removes PDB file reference) â”€â”€â”€â”€
        try:
            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.name == 'IMAGE_DIRECTORY_ENTRY_DEBUG':
                    fo = entry.get_file_offset()
                    result[fo:fo + 8] = b'\x00' * 8   # VirtualAddress + Size â†’ 0
                    break
        except Exception:
            pass

        # â”€â”€ 3. Overwrite CodeView RSDS PDB path strings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # RSDS record: 4-byte sig + 16-byte GUID + 4-byte age + null-term path
        try:
            src = bytes(result)
            idx = 0
            while True:
                idx = src.find(b'RSDS', idx)
                if idx == -1:
                    break
                ps = idx + 4 + 16 + 4       # skip sig + GUID + age
                pe_end = ps
                while pe_end < len(src) and src[pe_end] != 0:
                    pe_end += 1
                old_len = pe_end - ps
                if old_len > 4:
                    fake = f'C:\\Windows\\System32\\{arch_name}.pdb'.encode('ascii')
                    fake = fake[:old_len].ljust(old_len, b'\x00')
                    result[ps:pe_end] = fake
                idx = pe_end + 1
                src = bytes(result)
        except Exception:
            pass

        # â”€â”€ 4. Replace RT_MANIFEST with a clean preset manifest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        _MANIFEST = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\r\n'
            f'  <assemblyIdentity type="win32" name="{arch_name}"'
            f' version="{manifest_ver}" processorArchitecture="amd64"/>\r\n'
            '  <application>\r\n'
            '    <windowsSettings>\r\n'
            '      <dpiAwareness'
            ' xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">'
            'PerMonitorV2, PerMonitor</dpiAwareness>\r\n'
            '      <dpiAware'
            ' xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">'
            'True</dpiAware>\r\n'
            '    </windowsSettings>\r\n'
            '  </application>\r\n'
            '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\r\n'
            '    <security>\r\n'
            '      <requestedPrivileges>\r\n'
            '        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\r\n'
            '      </requestedPrivileges>\r\n'
            '    </security>\r\n'
            '  </trustInfo>\r\n'
            '</assembly>'
        ).encode('utf-8')
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if res_type.id != 24:   # RT_MANIFEST
                        continue
                    for res_id in res_type.directory.entries:
                        for res_lang in res_id.directory.entries:
                            off = pe.get_offset_from_rva(res_lang.data.struct.OffsetToData)
                            sz  = res_lang.data.struct.Size
                            if len(_MANIFEST) <= sz:
                                result[off:off + len(_MANIFEST)] = _MANIFEST
                                result[off + len(_MANIFEST):off + sz] = b'\x00' * (sz - len(_MANIFEST))
        except Exception:
            pass

        # â”€â”€ 5. Recalculate PE optional-header checksum â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            pe_tmp = _pefile.PE(data=bytes(result), fast_load=True)
            new_cs  = pe_tmp.generate_checksum()
            opt_off = pe_tmp.OPTIONAL_HEADER.get_file_offset()
            # CheckSum is at offset 64 from the start of the optional header
            # for both PE32 (32-bit) and PE32+ (64-bit).
            _struct.pack_into('<I', result, opt_off + 64, new_cs)
        except Exception:
            pass

        return bytes(result)
    except Exception:
        return exe_bytes


def _replace_pe_icons(exe_bytes: bytes, preset: str) -> bytes:
    """Replace RT_ICON resources in a PE file with brand-logo icons.

    Key correctness requirement: the PNG written into each RT_ICON slot must be
    at the EXACT pixel dimensions that RT_GROUP_ICON declares for that slot.
    Windows reads RT_GROUP_ICON to decide which RT_ICON to use for a given
    display size, then reads the actual PNG from that slot.  If the PNG
    dimensions don't match what RT_GROUP_ICON says, Windows may silently ignore
    the slot and show a blank or default icon.

    To fit large brand logos into the original (small) slot bytes we quantise
    the RGBA image to fewer unique colour values before PNG compression, which
    dramatically shrinks the DEFLATE output while keeping the PNG colour type as
    32-bit RGBA (the only type Windows accepts for icon PNGs).
    """
    cfg = _ICON_PRESETS.get(preset)
    if not cfg:
        return exe_bytes
    bg = cfg['bg']
    logo_file = cfg.get('logo_file', '')
    try:
        import pefile as _pefile
        pe = _pefile.PE(data=exe_bytes, fast_load=True)
        pe.parse_data_directories(directories=[
            _pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ])
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return exe_bytes

        # â”€â”€ Step 1: read RT_GROUP_ICON to learn which RT_ICON ID maps to which size â”€â”€
        # GRPICONDIRENTRY layout (14 bytes):
        #   BYTE bWidth, BYTE bHeight, BYTE bColorCount, BYTE bReserved,
        #   WORD wPlanes, WORD wBitCount, DWORD dwBytesInRes, WORD nId
        icon_id_to_size: dict[int, int] = {}  # icon_id â†’ pixel dimension (square)
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.id != _pefile.RESOURCE_TYPE['RT_GROUP_ICON']:
                continue
            for res_id in res_type.directory.entries:
                for res_lang in res_id.directory.entries:
                    off = pe.get_offset_from_rva(res_lang.data.struct.OffsetToData)
                    grp = exe_bytes[off:off + res_lang.data.struct.Size]
                    count = _struct.unpack_from('<H', grp, 4)[0]
                    for i in range(count):
                        e = 6 + i * 14
                        bW = grp[e]       # 0 means 256
                        n_id = _struct.unpack_from('<H', grp, e + 12)[0]
                        icon_id_to_size[n_id] = bW if bW > 0 else 256

        # â”€â”€ Step 2: patch each RT_ICON slot at the correct dimensions â”€â”€
        result = bytearray(exe_bytes)
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.id != _pefile.RESOURCE_TYPE['RT_ICON']:
                continue
            for res_id in res_type.directory.entries:
                icon_id = res_id.id  # matches nId in RT_GROUP_ICON
                px = icon_id_to_size.get(icon_id, 0)
                for res_lang in res_id.directory.entries:
                    rva = res_lang.data.struct.OffsetToData
                    orig_size = res_lang.data.struct.Size
                    file_off = pe.get_offset_from_rva(rva)
                    probe = bytes(exe_bytes[file_off:file_off + 8])

                    if probe[:4] == b'\x89PNG':
                        if px > 0:
                            # Generate PNG at exactly the right dimensions, quantised
                            # to reduce file size so it fits within orig_size bytes.
                            new_data = _make_png_for_slot(bg, px, logo_file, orig_size)
                        else:
                            new_data = b''
                    elif len(probe) >= 8:
                        # BMP slot
                        icon_w = abs(_struct.unpack('<i', probe[4:8])[0])
                        if icon_w <= 0 or icon_w > 512:
                            continue
                        new_data = _make_bmp_icon_data(bg, icon_w, logo_file)
                    else:
                        continue

                    if new_data and len(new_data) <= orig_size:
                        result[file_off:file_off + len(new_data)] = new_data
                        result[file_off + len(new_data):file_off + orig_size] = (
                            b'\x00' * (orig_size - len(new_data))
                        )

        return bytes(result)
    except Exception:
        return exe_bytes


def _fetch_release_binary_full() -> bytes | None:
    """Download the latest release EXE into memory so we can patch it."""
    release = _latest_release_data(direct_exe_only=True)
    if not release:
        return None
    asset_id = release.get('assetId')
    browser_download_url = str(release.get('browserDownloadUrl') or '').strip()
    if not asset_id:
        return None
    return _fetch_release_asset_bytes(int(asset_id), browser_download_url)


@web_bp.route('/api/dashboard/build-exe', methods=['POST'])
def dashboard_build_exe():
    """Build and return a metadata-patched EXE customised for the requesting user."""
    user, err = _dashboard_user_or_401()
    if err:
        return err
    if not _active_full_client_license(user):
        return jsonify({
            'ok': False,
            'error': 'subscription_required',
            'message': 'An active Divine subscription is required to build the client.',
        }), 403

    ip = _client_ip()
    limiter = get_limiter()
    if not limiter.check_and_record(f'web:build_exe:{ip}', 4, 60):
        return jsonify({'ok': False, 'error': 'Too many build requests â€” please wait a minute.'}), 429

    data = request.get_json(silent=True) or {}
    import re as _re

    # Sanitise inputs
    preset = str(data.get('preset') or '').strip().lower()
    file_name = (_re.sub(r'[^A-Za-z0-9._\- ]', '', str(data.get('fileName') or 'App'))[:60].strip() or 'App')
    display_name = str(data.get('displayName') or file_name)[:64].strip()
    company = str(data.get('company') or '')[:64].strip()
    version_str = (_re.sub(r'[^0-9.]', '', str(data.get('version') or '1.0.0.0'))[:20] or '1.0.0.0')
    description = str(data.get('description') or '')[:128].strip()

    # Fetch the base release binary
    exe_bytes = _fetch_release_binary_full()
    if not exe_bytes:
        return jsonify({'ok': False, 'error': 'Could not fetch release â€” try again shortly.'}), 503

    # Patch version resource strings
    patch_strings: dict[str, str] = {
        'FileDescription': description or display_name,
        'ProductName': display_name,
        'InternalName': file_name,
        'OriginalFilename': f'{file_name}.exe',
        'CompanyName': company,
        'ProductVersion': version_str,
        'FileVersion': version_str,
    }
    if company:
        patch_strings['LegalCopyright'] = f'Copyright \u00a9 {company}'

    patched = _patch_exe_version_strings(exe_bytes, patch_strings)

    # Optionally patch icons (graceful fallback if pefile/Pillow unavailable)
    if preset in _ICON_PRESETS:
        patched = _replace_pe_icons(patched, preset)

    # Patch the ZNTH_PRESET marker so the app knows its disguise preset at runtime.
    if preset:
        marker = b'ZNTH_PRESET:'
        payload = preset.encode('ascii', errors='replace')[:12].ljust(12, b'\x00')
        idx = patched.find(marker)
        if idx != -1:
            patched = bytearray(patched)
            patched[idx + len(marker):idx + len(marker) + 12] = payload
            patched = bytes(patched)

    # Strip compiler fingerprints, replace manifest, recalculate checksum
    if preset in _ICON_PRESETS:
        patched = _sanitize_pe_binary(patched, preset, version_str)

    safe_fname = _re.sub(r'[^A-Za-z0-9._\-]', '_', file_name)
    response = make_response(patched)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{safe_fname}.exe"'
    response.headers['Content-Length'] = str(len(patched))
    response.headers['Cache-Control'] = 'no-store'
    audit_event('web.build_exe.ok', ip=ip, user=str(user.get('id', '')), preset=preset,
                file_name=safe_fname, size=len(patched))
    return response


@web_bp.route('/api/client/latest', methods=['GET'])
def client_latest():
    release = _latest_release_data()
    if not release:
        return jsonify({'ok': False, 'error': 'Latest release is not configured yet'}), 503
    return jsonify({
        'ok': True,
        'version': release['version'],
        'publishedAt': release['publishedAt'],
        'assetName': release['assetName'],
        'size': release['assetSize'],
    }), 200


@web_bp.route('/api/affiliate/me', methods=['GET'])
def affiliate_me():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    uid = str(user.get('id') or '').strip()
    rows = _licenses_for_user(user)
    if not rows:
        return jsonify({'ok': False, 'error': 'no_affiliate'}), 200
    active = _choose_summary_license(rows)
    if not active:
        return jsonify({'ok': False, 'error': 'no_affiliate'}), 200
    meta = active.extra_metadata or {}
    aff_code = str(meta.get('affiliate_code') or '').strip()
    if not aff_code:
        return jsonify({'ok': False, 'error': 'no_affiliate'}), 200
    site = str(current_app.config.get('SITE_URL', 'https://divinemacros.store')).rstrip('/')

    # Compute stats from licenses that used this affiliate code
    all_lics = License.query.all()
    referred = [
        l for l in all_lics
        if str((l.extra_metadata or {}).get('affiliate_code', '')).strip().lower() == aff_code.lower()
        and str((l.extra_metadata or {}).get('discord_id', '')).strip() != uid
    ]
    total_sales = len(referred)
    gross_cents = sum(int((l.extra_metadata or {}).get('charged_cents', 0)) for l in referred)
    commission_rate = float(meta.get('aff_commission_rate', 0.20))
    commission_cents = int(gross_cents * commission_rate)
    paid_out_cents = int(meta.get('aff_paid_out_cents', 0))
    available_cents = max(0, commission_cents - paid_out_cents)

    recent = []
    for l in sorted(referred, key=lambda x: str(x.created_at or ''), reverse=True)[:10]:
        lm = l.extra_metadata or {}
        recent.append({
            'plan': _license_plan(l),
            'charged_cents': int(lm.get('charged_cents', 0)),
            'created_at': _license_created_iso(l),
        })

    # Build 14-day chart data
    from collections import defaultdict
    today = datetime.now(timezone.utc).date()
    day_buckets: dict[str, int] = defaultdict(int)
    for l in referred:
        try:
            iso = str(l.created_at or '')
            if iso:
                d = datetime.fromisoformat(iso.replace('Z', '+00:00')).date()
                if (today - d).days < 14:
                    day_buckets[d.isoformat()] += int((l.extra_metadata or {}).get('charged_cents', 0))
        except Exception:
            pass
    chart = []
    for i in range(13, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        gross = day_buckets.get(d, 0)
        chart.append({'date': d, 'commission_cents': int(gross * commission_rate)})

    return jsonify({
        'ok': True,
        'code': aff_code,
        'total_sales': total_sales,
        'gross_revenue_cents': gross_cents,
        'total_commission_cents': commission_cents,
        'available_cents': available_cents,
        'pending_cashouts_cents': 0,
        'referral_link_query': f'{site}/?ref={aff_code}',
        'referral_link_path': f'{site}/r/{aff_code}',
        'chart': chart,
        'recent_sales': recent,
    }), 200


@web_bp.route('/api/affiliate/create', methods=['POST'])
def affiliate_create():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    rows = _licenses_for_user(user)
    if not rows:
        return jsonify({'ok': False, 'error': 'No license found. Purchase a plan to access the affiliate program.'}), 403
    active = _choose_summary_license(rows)
    if not active:
        return jsonify({'ok': False, 'error': 'No active license found.'}), 403
    meta = dict(active.extra_metadata or {})
    if meta.get('affiliate_code'):
        return jsonify({'ok': True, 'code': meta['affiliate_code']}), 200
    code = 'zen' + secrets.token_hex(3)  # 6 random hex chars â†’ e.g. zena3f9c2
    # ensure uniqueness via indexed column
    while License.query.filter(License.affiliate_code == code).first():
        code = 'zen' + secrets.token_hex(3)
    meta['affiliate_code'] = code
    active.extra_metadata = meta
    active.affiliate_code = code
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'ok': False, 'error': 'Database error. Please try again.'}), 500
    return jsonify({'ok': True, 'code': code}), 200


@web_bp.route('/api/affiliate/cashout', methods=['POST'])
def affiliate_cashout():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    return jsonify({
        'ok': False,
        'error': 'Cashout requests must be submitted via a Discord support ticket. Join our server and open a ticket.',
    }), 200


@web_bp.route('/api/dashboard/claim-legacy', methods=['POST'])
def dashboard_claim_legacy():
    user, err = _dashboard_user_or_401()
    if err:
        return err
    if not request.is_json:
        return jsonify({'ok': False, 'error': 'Invalid request'}), 400
    body = request.get_json(silent=True) or {}
    raw_key = str(body.get('key') or '').strip().upper().replace('-', '')
    if len(raw_key) < 6:
        return jsonify({'ok': False, 'error': 'Please enter a valid license key.'}), 400
    uid = str(user.get('id') or '').strip()
    all_rows = License.query.order_by(License.id.desc()).limit(5000).all()
    for lic in all_rows:
        norm_key = str(lic.key or '').strip().upper().replace('-', '')
        if norm_key == raw_key:
            meta = dict(lic.extra_metadata or {})
            existing_owner = str(meta.get('discord_id') or meta.get('discordId') or '').strip()
            if existing_owner and existing_owner != uid:
                return jsonify({'ok': False, 'error': 'This key is already linked to another account.'}), 409
            meta['discord_id'] = uid
            meta['claimed_via'] = 'dashboard'
            lic.extra_metadata = meta
            try:
                db.session.commit()
                return jsonify({'ok': True, 'message': 'Key successfully linked to your account.'}), 200
            except Exception:
                db.session.rollback()
                return jsonify({'ok': False, 'error': 'Database error. Please try again.'}), 500
    return jsonify({'ok': False, 'error': 'Key not found. Check the key and try again, or contact support.'}), 404


@web_bp.route('/api/debug/session', methods=['GET'])
def debug_session():
    cookie_name = str(current_app.config.get('DASHBOARD_COOKIE_NAME', 'zenith_dash'))
    raw = request.cookies.get(cookie_name, '')
    decoded = _decode_session_payload(raw) if raw else None
    return jsonify({
        'cookie_name': cookie_name,
        'cookie_present': bool(raw),
        'cookie_len': len(raw),
        'all_cookies': list(request.cookies.keys()),
        'decode_ok': decoded is not None,
        'user': (decoded.get('user', {}).get('id', 'no_id') if decoded else None),
        'is_secure': request.is_secure,
        'scheme': request.scheme,
        'secret_len': len(_session_secret()),
    })


@web_bp.route('/healthz', methods=['GET'])
def healthz():
    try:
        db.session.execute(db.text('SELECT 1'))
        resp = {
            'ok': True,
            'uptimeSec': int(time.time()),
            'timestamp': _utc_now().isoformat(),
        }
        return jsonify(resp), 200
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 503


@web_bp.route('/', methods=['GET'])
def web_index():
    # Allow Discord OAuth redirect URIs that point to "/" by forwarding
    # callback params into the canonical callback handler.
    if request.args.get('code') or request.args.get('state') or request.args.get('error'):
        query = request.query_string.decode('utf-8', errors='ignore')
        target = '/auth/discord/callback'
        if query:
            target = f'{target}?{query}'
        return redirect(target, code=302)

    target = _safe_web_path('index.html')
    if target is None or not target.exists():
        return make_response('Website not found', 404)
    return send_file(target)


@web_bp.route('/<path:asset_path>', methods=['GET'])
def web_assets(asset_path: str):
    normalized = str(asset_path or '').strip().replace('\\', '/')
    if not normalized:
        return make_response('Not found', 404)

    lowered = normalized.lower()
    if lowered in {'index', 'index.html'}:
        qs = request.query_string.decode('utf-8', errors='ignore')
        target_url = ('/' + ('#' + qs.lstrip('#')) if qs.startswith('#') else ('/?'+qs if qs else '/'))
        return redirect(target_url, code=301)

    if lowered.endswith('.html'):
        clean_path = normalized[:-5]
        if clean_path and clean_path.lower() != 'index':
            qs = request.query_string.decode('utf-8', errors='ignore')
            target_url = f'/{clean_path}'
            if qs:
                target_url = f'{target_url}?{qs}'
            return redirect(target_url, code=301)

    if lowered.startswith('api/') or lowered.startswith('v1/') or lowered.startswith('auth/'):
        return make_response('Not found', 404)

    # Keep dashboard route renderable even without a session to avoid auth loops.
    # API endpoints remain protected and dashboard.js already shows login state.

    target = _safe_web_path(normalized)
    if (target is None or (not target.exists()) or target.is_dir()) and '.' not in normalized:
        target = _safe_web_path(f'{normalized}.html')
    if target is None or (not target.exists()) or target.is_dir():
        return make_response('Not found', 404)
    resp = make_response(send_file(target))
    if normalized.endswith('.js') or normalized.endswith('.css') or normalized.endswith('.html'):
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp


# ---------------------------------------------------------------------------
# Stripe webhook â€” fulfills purchases by creating a License in the DB
# ---------------------------------------------------------------------------

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _generate_license_key() -> str:
    """Generate a Divine-prefixed key using the same alphabet as the bot.
    Avoids ambiguous characters (0/O, 1/I/l)."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return 'DIVN' + ''.join(secrets.choice(alphabet) for _ in range(12))


def _send_license_email(lic: License, user_email: str = '') -> None:
    """Send license key delivery email via SMTP if configured."""
    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_host = str(current_app.config.get('SMTP_HOST', '')).strip()
    smtp_port = int(current_app.config.get('SMTP_PORT', 587) or 587)
    smtp_user = str(current_app.config.get('SMTP_USER', '')).strip()
    smtp_pass = str(current_app.config.get('SMTP_PASS', '')).strip()
    email_from = str(current_app.config.get('EMAIL_FROM', smtp_user)).strip()

    meta = lic.extra_metadata or {}
    to_email = user_email or str(meta.get('email', '')).strip()
    if not smtp_host or not smtp_user or not smtp_pass or not to_email:
        return

    plan = _license_plan(lic)
    key_display = str(lic.key or '')
    # Format key nicely as XXXX-XXXX-XXXX-XXXX-XXXX (groups of 4)
    if len(key_display) >= 8:
        key_display = '-'.join(key_display[i:i+4] for i in range(0, len(key_display), 4))

    subject = 'Your Divine Macros License Key'
    body = f"""Hi there,

Thank you for your purchase of Divine Macros ({plan} plan)!

Your license key is:

  {key_display}

You can also view and manage your key at any time on your dashboard:
  https://divinemacros.store/dashboard

To activate, paste your key into the Divine Macros client when prompted.

If you have any issues, join our Discord server for support.

â€” The Divine Macros Team
"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = to_email
        msg.attach(MIMEText(body, 'plain'))

        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(smtp_user, smtp_pass)
            server.sendmail(email_from, [to_email], msg.as_string())
    except Exception as exc:
        audit_event('web.email.failed', error=str(exc)[:200])


def _send_cancellation_email(to_email: str, plan: str = 'monthly') -> None:
    """Send a subscription cancellation confirmation email."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_host  = str(current_app.config.get('SMTP_HOST', '')).strip()
    smtp_port  = int(current_app.config.get('SMTP_PORT', 587) or 587)
    smtp_user  = str(current_app.config.get('SMTP_USER', '')).strip()
    smtp_pass  = str(current_app.config.get('SMTP_PASS', '')).strip()
    email_from = str(current_app.config.get('EMAIL_FROM', smtp_user)).strip()

    if not smtp_host or not smtp_user or not smtp_pass or not to_email:
        return

    subject = 'Your Divine Macros subscription has been cancelled'
    body = f"""Hi there,

We're confirming that your Divine Macros {plan} subscription has been cancelled.

You'll keep access until the end of your current billing period.

If you cancelled by mistake or want to resubscribe, you can do so anytime at:
  https://divinemacros.store/#pricing

If you have any questions or feedback, feel free to reach out on our Discord.

â€” The Divine Macros Team
"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = email_from
        msg['To']      = to_email
        msg.attach(MIMEText(body, 'plain'))
        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(smtp_user, smtp_pass)
            server.sendmail(email_from, [to_email], msg.as_string())
        audit_event('web.email.cancellation_sent', email=to_email[:6] + '***')
    except Exception as exc:
        audit_event('web.email.failed', error=str(exc)[:200])


def _send_referrer_dm(affiliate_code: str, buyer_discord_id: str, plan: str) -> None:
    """DM the affiliate code owner when someone uses their referral code."""
    import sys as _sys
    bot_token = str(current_app.config.get('DISCORD_BOT_TOKEN', '')).strip()
    if not bot_token or not affiliate_code:
        return

    # Look up who owns this affiliate code
    try:
        owner_lic = License.query.filter(
            License.affiliate_code == affiliate_code.lower()
        ).first()
        if not owner_lic:
            return
        owner_meta   = owner_lic.extra_metadata or {}
        owner_discord = str(owner_meta.get('discord_id', '')).strip()
        if not owner_discord:
            return
        # Never DM the buyer themselves (shouldn't happen â€” validated at checkout â€” but be safe)
        if owner_discord == buyer_discord_id:
            return
    except Exception as exc:
        print(f'[referrer_dm] lookup failed code={affiliate_code} error={exc}', file=_sys.stderr)
        return

    normalized_plan = _normalize_checkout_plan(plan)
    if normalized_plan == 'core_lifetime':
        plan_label = 'Core Lifetime license'
    elif normalized_plan == 'pro_lifetime':
        plan_label = 'Pro Lifetime license'
    elif normalized_plan == 'pro_monthly':
        plan_label = 'Pro Monthly subscription'
    else:
        plan_label = 'Core Monthly subscription'

    embed = {
        'title': 'ðŸŽ‰ Someone Used Your Referral Code!',
        'color': 0xffd60a,
        'description': (
            f'Great news â€” someone just purchased a **{plan_label}** using your referral code **`{affiliate_code}`**! ðŸ”¥\n\n'
            'Your commission has been tracked and will be added to your affiliate balance.\n\n'
            '**Check your stats anytime:**\n'
            '> Log into **https://divinemacros.store/dashboard** and open the **Affiliate** tab\n\n'
            '**Keep sharing your link to earn more:**\n'
            f'> `divinemacros.store/?ref={affiliate_code}`\n\n'
            'ðŸ’œ Thank you for supporting Divine Macros!'
        ),
        'footer': {'text': 'Divine Macros Affiliate Program'},
    }

    try:
        from urllib.request import Request as _Req, urlopen as _open
        dm_body = json.dumps({'recipient_id': owner_discord}).encode()
        dm_req  = _Req(
            'https://discord.com/api/v10/users/@me/channels',
            data=dm_body,
            headers={'Authorization': f'Bot {bot_token}', 'Content-Type': 'application/json'},
            method='POST',
        )
        with _open(dm_req, timeout=8) as resp:
            dm_channel = json.loads(resp.read())
        channel_id = dm_channel.get('id', '')
        if not channel_id:
            return
        msg_body = json.dumps({'embeds': [embed]}).encode()
        msg_req  = _Req(
            f'https://discord.com/api/v10/channels/{channel_id}/messages',
            data=msg_body,
            headers={'Authorization': f'Bot {bot_token}', 'Content-Type': 'application/json'},
            method='POST',
        )
        with _open(msg_req, timeout=8) as _:
            pass
    except Exception as exc:
        print(f'[referrer_dm] send failed owner={owner_discord} code={affiliate_code} error={exc}', file=_sys.stderr)


def _send_purchase_dm(discord_id: str, plan: str, product_name: str | None = None) -> None:
    """DM the buyer via Discord bot token with a thank-you and onboarding message."""
    import sys as _sys
    bot_token = str(current_app.config.get('DISCORD_BOT_TOKEN', '')).strip()
    if not bot_token or not discord_id:
        return

    is_standalone = plan.startswith('standalone:')
    if is_standalone:
        item_label = product_name or plan.removeprefix('standalone:')
        purchase_line = f'your **{item_label}** individual macro'
    elif _normalize_checkout_plan(plan) == 'core_lifetime':
        purchase_line = 'your **Core Lifetime** Divine Macros license'
    elif _normalize_checkout_plan(plan) == 'pro_lifetime':
        purchase_line = 'your **Pro Lifetime** Divine Macros license'
    elif _normalize_checkout_plan(plan) == 'pro_monthly':
        purchase_line = 'your **Pro Monthly** Divine Macros subscription'
    else:
        purchase_line = 'your **Core Monthly** Divine Macros subscription'

    embed = {
        'title': 'ðŸŽ‰ Thanks for Your Purchase!',
        'color': 0x8b5cf6,
        'description': (
            f'Thank you for purchasing {purchase_line}! We really appreciate your support. ðŸ’œ\n\n'
            '**Here\'s how to get started:**\n'
            '1. Head to **https://divinemacros.store/** and log in with your Discord account\n'
            '2. Click **Dashboard** â€” your license key will be right there\n'
            '3. On the left sidebar, click **Downloads** to grab the latest version\n\n'
            'ðŸ“º **Need help? Watch our setup videos:**\n'
            '> https://www.youtube.com/watch?v=dS28782lZn4\n'
            '> https://www.youtube.com/watch?v=FRY-vCEq9iU&t=48s\n\n'
            '**Have questions or suggestions?**\n'
            'â€¢ Open a **support ticket** in our Discord server for help\n'
            'â€¢ Drop ideas in the **#suggestions** channel â€” we\'d love your feedback!\n\n'
            'â­ **Enjoying Divine Macros?** Use `/rating` in our Discord server to leave a review â€” it means the world to us!'
        ),
        'footer': {'text': 'Divine Macros â€¢ Thank you for your support!'},
    }

    try:
        from urllib.request import Request as _Req, urlopen as _open
        # Step 1: create DM channel
        dm_body = json.dumps({'recipient_id': discord_id}).encode()
        dm_req = _Req(
            'https://discord.com/api/v10/users/@me/channels',
            data=dm_body,
            headers={
                'Authorization': f'Bot {bot_token}',
                'Content-Type': 'application/json',
            },
            method='POST',
        )
        with _open(dm_req, timeout=8) as resp:
            dm_channel = json.loads(resp.read())
        channel_id = dm_channel.get('id', '')
        if not channel_id:
            return
        # Step 2: send message
        msg_body = json.dumps({'embeds': [embed]}).encode()
        msg_req = _Req(
            f'https://discord.com/api/v10/channels/{channel_id}/messages',
            data=msg_body,
            headers={
                'Authorization': f'Bot {bot_token}',
                'Content-Type': 'application/json',
            },
            method='POST',
        )
        with _open(msg_req, timeout=8) as _:
            pass
    except Exception as exc:
        print(f'[purchase_dm] failed discord_id={discord_id} error={exc}', file=_sys.stderr)


def _post_sale_notification(discord_id: str, plan: str, charged_cents: int,
                            license_key: str = '', user_email: str = '',
                            stripe_ref: str = '', affiliate_code: str | None = None,
                            product_name: str | None = None) -> None:
    """Post a sale notification via Discord webhook URL or bot channel message."""
    import sys as _sys
    from datetime import datetime, timezone as _tz

    amount = f'${charged_cents / 100:.2f}'
    is_standalone = plan.startswith('standalone:')

    if is_standalone:
        plan_label = product_name or plan.removeprefix('standalone:')
        plan_color = 0xffd60a   # green for individual macros
        title = f'ðŸŽ‰ Individual Macro Sale â€” {plan_label}'
        footer_text = 'Divine Macros â€¢ Individual Macros'
    else:
        normalized_plan = _normalize_checkout_plan(plan)
        if normalized_plan == 'core_lifetime':
            plan_label = 'Core Lifetime'
            plan_color = 0x10bb82
        elif normalized_plan == 'pro_lifetime':
            plan_label = 'Pro Lifetime'
            plan_color = 0x7c3aed
        elif normalized_plan == 'pro_monthly':
            plan_label = 'Pro Monthly'
            plan_color = 0xffd60a
        else:
            plan_label = 'Core Monthly'
            plan_color = 0x6366f1
        title = 'ðŸŽ‰ New Sale â€” Divine Macros'
        footer_text = 'Divine Macros â€¢ Purchase System'

    key_display = license_key
    if len(key_display) >= 8:
        key_display = '-'.join(key_display[i:i+4] for i in range(0, len(key_display), 4))

    fields = [
        {'name': 'ðŸ‘¤ Buyer', 'value': f'<@{discord_id}>', 'inline': True},
        {'name': 'ðŸ“¦ ' + ('Product' if is_standalone else 'Plan'), 'value': plan_label, 'inline': True},
        {'name': 'ðŸ’° Amount', 'value': amount, 'inline': True},
    ]
    if user_email:
        fields.append({'name': 'ðŸ“§ Email', 'value': user_email, 'inline': True})
    if key_display:
        fields.append({'name': 'ðŸ”‘ License Key', 'value': f'`{key_display}`', 'inline': False})
    if affiliate_code:
        fields.append({'name': 'ðŸ”— Referral', 'value': f'`{affiliate_code}`', 'inline': True})
    if stripe_ref:
        short_ref = stripe_ref[:24] + 'â€¦' if len(stripe_ref) > 24 else stripe_ref
        fields.append({'name': 'ðŸ§¾ Stripe Ref', 'value': f'`{short_ref}`', 'inline': True})

    embed = {
        'title': title,
        'color': plan_color,
        'fields': fields,
        'footer': {'text': footer_text},
        'timestamp': datetime.now(_tz.utc).isoformat(),
    }
    body = json.dumps({'embeds': [embed]}).encode()

    # Prefer DISCORD_ORDER_WEBHOOK (webhook URL) if set
    webhook_url = str(current_app.config.get('DISCORD_ORDER_WEBHOOK', '')).strip()
    if webhook_url:
        try:
            req = Request(webhook_url, data=body, headers={
                'Content-Type': 'application/json',
                'User-Agent': 'DiscordBot (https://divinemacros.store, 1.0)',
            }, method='POST')
            with urlopen(req, timeout=8) as resp:
                resp.read()
            return
        except Exception as exc:
            print(f'[sale_notification] webhook failed discord_id={discord_id} error={exc}', file=_sys.stderr)
        return

    # Fall back to bot API + channel ID
    bot_token = str(current_app.config.get('DISCORD_BOT_TOKEN', '')).strip()
    channel_id = str(current_app.config.get('DISCORD_SALE_CHANNEL_ID', '')).strip()
    if not bot_token or not channel_id:
        print(f'[sale_notification] no webhook URL and no bot_token/channel_id configured', file=_sys.stderr)
        return
    try:
        req = Request(
            f'https://discord.com/api/v10/channels/{channel_id}/messages',
            data=body,
            headers={
                'Authorization': f'Bot {bot_token}',
                'Content-Type': 'application/json',
            },
            method='POST',
        )
        with urlopen(req, timeout=8) as resp:
            resp.read()
    except Exception as exc:
        print(f'[sale_notification] bot API failed discord_id={discord_id} channel={channel_id} error={exc}', file=_sys.stderr)


def _fulfill_purchase(stripe_ref: str, discord_id: str, plan: str, charged_cents: int,
                      affiliate_code: str | None, coupon_code: str | None,
                      user_email: str = '', stripe_customer: str = '') -> None:
    existing = License.query.filter(
        License._metadata.like(f'%"stripe_ref": "{stripe_ref}"%')
    ).first()
    if existing:
        return

    normalized = _generate_license_key()
    while License.query.filter_by(key_hash=_sha256_hex(normalized)).first() is not None:
        normalized = _generate_license_key()

    plan = _normalize_checkout_plan(plan)

    if plan in {'core_monthly', 'pro_monthly'}:
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    else:
        expires_at = None

    meta: dict = {
        'discord_id': discord_id,
        'plan': plan,
        'stripe_ref': stripe_ref,
        'charged_cents': charged_cents,
    }
    if affiliate_code:
        meta['affiliate_code'] = affiliate_code
    if coupon_code:
        meta['coupon_code'] = coupon_code
    if user_email:
        meta['user_email'] = user_email
    if stripe_customer:
        meta['stripe_customer'] = stripe_customer

    lic = License(
        key=normalized,
        key_hash=_sha256_hex(normalized),
        user_enc_key=secrets.token_hex(32),
        user_salt=secrets.token_hex(16),
        hwid_change_count=0,
        tier=plan,
        is_revoked=False,
        expires_at=expires_at,
    )
    lic.extra_metadata = meta
    db.session.add(lic)
    db.session.commit()
    audit_event('web.stripe.fulfilled', license_id=lic.id, plan=plan, discord_id=discord_id)
    _send_license_email(lic, user_email=user_email)
    _post_sale_notification(discord_id, plan, charged_cents,
                            license_key=str(lic.key or ''),
                            user_email=user_email,
                            stripe_ref=stripe_ref,
                            affiliate_code=affiliate_code)
    _send_purchase_dm(discord_id, plan)
    if affiliate_code:
        _send_referrer_dm(affiliate_code, discord_id, plan)
    grant_customer_role(discord_id, current_app.config)


def _renew_subscription_license(
    invoice_ref: str,
    discord_id: str,
    plan: str,
    charged_cents: int,
    stripe_customer: str,
    stripe_subscription: str,
    user_email: str = '',
) -> bool:
    """Extend one monthly license once for a paid recurring Stripe invoice."""
    invoice_ref = str(invoice_ref or '').strip()
    discord_id = str(discord_id or '').strip()
    stripe_customer = str(stripe_customer or '').strip()
    plan = _normalize_checkout_plan(plan)
    if not invoice_ref or plan not in {'core_monthly', 'pro_monthly'}:
        return False

    candidates = License.query.filter_by(is_revoked=False).order_by(License.id.desc()).all()
    selected = None
    for row in candidates:
        meta = row.extra_metadata or {}
        processed = list(meta.get('stripe_invoice_refs') or [])
        if invoice_ref in processed:
            return True
        customer_matches = stripe_customer and str(meta.get('stripe_customer') or '') == stripe_customer
        discord_matches = discord_id and str(meta.get('discord_id') or '') == discord_id
        if _license_plan(row) == plan and (customer_matches or discord_matches):
            selected = row
            break

    if selected is None:
        if not discord_id:
            return False
        _fulfill_purchase(
            invoice_ref,
            discord_id,
            plan,
            charged_cents,
            None,
            None,
            user_email,
            stripe_customer=stripe_customer,
        )
        return True

    now = datetime.now(timezone.utc)
    current_expiry = selected.expires_at
    if current_expiry is not None and current_expiry.tzinfo is None:
        current_expiry = current_expiry.replace(tzinfo=timezone.utc)
    selected.expires_at = max(now, current_expiry or now) + timedelta(days=30)
    selected.is_revoked = False

    meta = selected.extra_metadata or {}
    processed = list(meta.get('stripe_invoice_refs') or [])
    processed.append(invoice_ref)
    meta['stripe_invoice_refs'] = processed[-24:]
    meta['last_stripe_invoice'] = invoice_ref
    meta['last_renewed_at'] = now.isoformat()
    meta['charged_cents'] = int(charged_cents or 0)
    if stripe_customer:
        meta['stripe_customer'] = stripe_customer
    if stripe_subscription:
        meta['stripe_subscription'] = stripe_subscription
    if user_email:
        meta['user_email'] = user_email
    selected.extra_metadata = meta
    db.session.commit()
    audit_event(
        'web.stripe.renewed',
        license_id=selected.id,
        plan=plan,
        discord_id=discord_id,
        invoice_ref=invoice_ref,
    )
    return True


@web_bp.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    webhook_secret = str(current_app.config.get('STRIPE_WEBHOOK_SECRET', '')).strip()
    if not webhook_secret:
        return jsonify({'ok': False, 'error': 'Webhook not configured'}), 501

    payload = request.get_data()
    sig = request.headers.get('Stripe-Signature', '')

    try:
        import stripe as _stripe
        event = _stripe.Webhook.construct_event(payload, sig, webhook_secret)
    except Exception:
        return jsonify({'ok': False}), 400

    # stripe-python v5+ returns StripeObjects that lack .get(); convert to plain dict
    try:
        event_dict = event.to_dict()
    except Exception:
        event_dict = dict(event)

    et = event_dict.get('type', '')
    obj = (event_dict.get('data') or {}).get('object') or {}
    meta = dict(obj.get('metadata') or {})

    discord_id = str(meta.get('discord_id', '')).strip()
    plan = _normalize_checkout_plan(meta.get('plan', 'monthly'))
    affiliate_code = meta.get('affiliate_code') or None
    coupon_code = meta.get('coupon_code') or None

    if et in {'checkout.session.completed', 'checkout.session.async_payment_succeeded'} and discord_id:
        if et == 'checkout.session.completed' and str(obj.get('payment_status') or '') not in {'paid', 'no_payment_required'}:
            return jsonify({'ok': True, 'pending': True}), 200
        stripe_ref = str(obj.get('payment_intent') or obj.get('id') or '')
        charged_cents = int(obj.get('amount_total') or 0)
        customer_details = obj.get('customer_details') or {}
        user_email = str(
            customer_details.get('email') or obj.get('customer_email') or ''
        ).strip()
        stripe_customer = str(obj.get('customer') or '').strip()

        if meta.get('type') == 'standalone':
            # Support multi-product cart (product_ids) and single product (product_id)
            pids_raw = str(meta.get('product_ids') or meta.get('product_id') or '').strip()
            pids = [p.strip() for p in pids_raw.split(',') if p.strip()]
            # Distribute the total charge evenly across products so the sale
            # notification shows the real price instead of $0.00
            per_product_cents = (charged_cents // len(pids)) if pids else 0
            for pid in pids:
                _fulfill_standalone(stripe_ref + f':{pid}', discord_id, pid, per_product_cents, user_email)
        else:
            _fulfill_purchase(stripe_ref, discord_id, plan, charged_cents, affiliate_code, coupon_code, user_email, stripe_customer=stripe_customer)

    elif et == 'payment_intent.succeeded' and discord_id:
        stripe_ref = str(obj.get('id') or '')
        charged_cents = int(obj.get('amount_received') or obj.get('amount') or 0)
        if meta.get('type') == 'standalone':
            pids_raw = str(meta.get('product_ids') or meta.get('product_id') or '').strip()
            pids = [pid.strip() for pid in pids_raw.split(',') if pid.strip()]
            per_product_cents = (charged_cents // len(pids)) if pids else 0
            for pid in pids:
                _fulfill_standalone(f'{stripe_ref}:{pid}', discord_id, pid, per_product_cents)
        else:
            _fulfill_purchase(stripe_ref, discord_id, plan, charged_cents, affiliate_code, coupon_code)

    elif et == 'invoice.paid' and str(obj.get('billing_reason') or '') != 'subscription_create':
        invoice_ref = str(obj.get('id') or '').strip()
        stripe_customer = str(obj.get('customer') or '').strip()
        stripe_subscription = str(obj.get('subscription') or '').strip()
        if not stripe_subscription:
            parent = obj.get('parent') or {}
            subscription_details = parent.get('subscription_details') or {}
            stripe_subscription = str(subscription_details.get('subscription') or '').strip()

        subscription_meta = {}
        if stripe_subscription:
            try:
                import stripe as _stripe
                _stripe.api_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
                subscription = _stripe.Subscription.retrieve(stripe_subscription)
                try:
                    subscription_meta = dict(subscription.metadata or {})
                except Exception:
                    subscription_meta = dict((subscription.to_dict() or {}).get('metadata') or {})
            except Exception:
                subscription_meta = {}

        renewal_meta = {**subscription_meta, **meta}
        renewal_discord_id = str(renewal_meta.get('discord_id') or '').strip()
        renewal_plan = _normalize_checkout_plan(renewal_meta.get('plan') or 'core_monthly')
        customer_email = str(obj.get('customer_email') or '').strip()
        charged_cents = int(obj.get('amount_paid') or 0)
        renewed = _renew_subscription_license(
            invoice_ref,
            renewal_discord_id,
            renewal_plan,
            charged_cents,
            stripe_customer,
            stripe_subscription,
            customer_email,
        )
        if not renewed:
            audit_event(
                'web.stripe.renewal_unmatched',
                invoice_ref=invoice_ref,
                customer=stripe_customer,
                subscription=stripe_subscription,
            )

    elif et == 'customer.subscription.deleted':
        # Subscription fully cancelled â€” send confirmation email
        customer_id = str(obj.get('customer') or '').strip()
        cancel_plan  = str((obj.get('metadata') or {}).get('plan', 'monthly')).strip() or 'monthly'
        user_email   = ''

        # Try to get email from Stripe customer object
        if customer_id:
            try:
                import stripe as _stripe
                stripe_key = str(current_app.config.get('STRIPE_SECRET_KEY', '')).strip()
                _stripe.api_key = stripe_key
                customer = _stripe.Customer.retrieve(customer_id)
                user_email = str(getattr(customer, 'email', '') or '').strip()
            except Exception:
                pass

        # Fall back: look up email in license metadata
        if not user_email and customer_id:
            lic = License.query.filter(
                License._metadata.like(f'%"stripe_customer": "{customer_id}"%')
            ).first()
            if lic:
                user_email = str((lic.extra_metadata or {}).get('email', '')).strip()

        if user_email:
            with current_app.app_context():
                _send_cancellation_email(user_email, cancel_plan)

        audit_event('web.subscription.cancelled', customer=customer_id, email=user_email[:6] + '***' if user_email else '')

    return jsonify({'ok': True})


@web_bp.route('/api/admin/test-discord', methods=['POST'])
def test_discord():
    """Admin endpoint to test Discord role grant and webhook notification."""
    data = request.get_json(silent=True) or {}
    # Accept either dashboard session OR admin token for quick testing
    token = str(data.get('token') or request.headers.get('X-Admin-Token') or '').strip()
    expected = str(current_app.config.get('BOT_API_TOKEN', '') or current_app.config.get('ADMIN_SECRET', '')).strip()
    if not token or not expected or token != expected:
        user, err = _dashboard_user_or_401()
        if err:
            return err
        discord_id = str(data.get('discord_id') or user.get('id') or '').strip()
    else:
        discord_id = str(data.get('discord_id') or '').strip()
    if not discord_id:
        return jsonify({'ok': False, 'error': 'No discord_id'}), 400
    if not discord_id:
        return jsonify({'ok': False, 'error': 'No discord_id'}), 400

    results = {}

    # Test role grant
    bot_token = str(current_app.config.get('DISCORD_BOT_TOKEN', '')).strip()
    guild_id = str(current_app.config.get('DISCORD_GUILD_ID', '')).strip()
    role_id = str(current_app.config.get('DISCORD_CUSTOMER_ROLE_ID', '')).strip()
    results['role_config'] = {
        'has_bot_token': bool(bot_token),
        'guild_id': guild_id,
        'role_id': role_id,
    }
    if bot_token and guild_id and role_id:
        url = f'https://discord.com/api/v10/guilds/{guild_id}/members/{discord_id}/roles/{role_id}'
        try:
            from urllib.request import Request as _Req, urlopen as _open
            from urllib.error import HTTPError as _HTTPError
            req = _Req(url, data=b'', headers={
                'Authorization': f'Bot {bot_token}',
                'Content-Type': 'application/json',
            }, method='PUT')
            with _open(req, timeout=8) as resp:
                results['role_grant'] = {'ok': True, 'status': resp.status}
        except _HTTPError as exc:
            body = exc.read(512).decode(errors='replace')
            results['role_grant'] = {'ok': False, 'status': exc.code, 'body': body}
        except Exception as exc:
            results['role_grant'] = {'ok': False, 'error': str(exc)}

    # Test webhook notification
    webhook_url = str(current_app.config.get('DISCORD_ORDER_WEBHOOK', '')).strip()
    results['webhook_config'] = {'has_webhook_url': bool(webhook_url)}
    if webhook_url:
        try:
            body = json.dumps({'content': f'ðŸ”§ Test notification for <@{discord_id}>'}).encode()
            from urllib.request import Request as _Req, urlopen as _open
            req = _Req(webhook_url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'DiscordBot (https://divinemacros.store, 1.0)'}, method='POST')
            with _open(req, timeout=8) as resp:
                results['webhook'] = {'ok': True, 'status': resp.status}
        except Exception as exc:
            results['webhook'] = {'ok': False, 'error': str(exc)}

    return jsonify({'ok': True, 'results': results})


@web_bp.route('/api/admin/lookup-license', methods=['POST'])
def admin_lookup_license():
    """Admin endpoint: look up a license by email or stripe_ref and optionally resend it."""
    data = request.get_json(silent=True) or {}
    token = str(data.get('token') or request.headers.get('X-Admin-Token') or '').strip()
    expected = str(current_app.config.get('BOT_API_TOKEN', '') or current_app.config.get('ADMIN_SECRET', '')).strip()
    authed = token and expected and token == expected
    if not authed:
        user, err = _dashboard_user_or_401()
        if err:
            return err

    email = str(data.get('email', '')).strip().lower()
    stripe_ref = str(data.get('stripe_ref', '')).strip()
    resend = bool(data.get('resend', False))

    licenses = []
    if email:
        all_lics = License.query.all()
        for l in all_lics:
            meta = l.extra_metadata or {}
            lic_email = str(meta.get('email', '')).strip().lower()
            # Also check user_email stored in metadata
            lic_user_email = str(meta.get('user_email', '')).strip().lower()
            if email in (lic_email, lic_user_email):
                licenses.append(l)
    elif stripe_ref:
        licenses = License.query.filter(
            License._metadata.like(f'%"{stripe_ref}"%')
        ).all()

    if not licenses:
        return jsonify({'ok': False, 'error': 'No license found', 'email': email, 'stripe_ref': stripe_ref}), 404

    results = []
    for lic in licenses:
        meta = lic.extra_metadata or {}
        entry = {
            'id': lic.id,
            'key': str(lic.key or ''),
            'tier': lic.tier,
            'is_revoked': lic.is_revoked,
            'expires_at': lic.expires_at.isoformat() if lic.expires_at else None,
            'discord_id': meta.get('discord_id', ''),
            'stripe_ref': meta.get('stripe_ref', ''),
            'plan': meta.get('plan', ''),
        }
        if resend and email:
            try:
                _send_license_email(lic, user_email=email)
                entry['resent'] = True
            except Exception as exc:
                entry['resent'] = False
                entry['resend_error'] = str(exc)[:200]
        results.append(entry)

    return jsonify({'ok': True, 'licenses': results})


# ---------------------------------------------------------------------------
# Admin: product catalog + entitlement management
# ---------------------------------------------------------------------------

def _require_admin_token():
    """Returns None if authed, or a Response if not."""
    data = request.get_json(silent=True) or {}
    token = str(data.get('token') or request.headers.get('X-Admin-Token') or '').strip()
    expected = str(current_app.config.get('BOT_API_TOKEN', '') or
                   current_app.config.get('ADMIN_SECRET', '')).strip()
    if token and expected and token == expected:
        return None, data
    user, auth_err = _dashboard_user_or_401()
    if not auth_err and user:
        discord_id = str(user.get('id') or '').strip()
        if discord_id and _verified_role_for_discord(discord_id) == 'admin':
            return None, data
    return jsonify({'ok': False, 'error': 'Admin token required'}), data


@web_bp.route('/api/admin/products', methods=['GET'])
def admin_list_products():
    err, _ = _require_admin_token()
    if err:
        return err
    products = Product.query.order_by(Product.sort_order).all()
    return jsonify({'ok': True, 'items': [
        {**p.to_dict(), 'stripe_price_id': p.stripe_price_id, 'download_ref': p.download_ref}
        for p in products
    ]}), 200


@web_bp.route('/api/admin/products', methods=['POST'])
def admin_create_product():
    err, data = _require_admin_token()
    if err:
        return err
    pid = str(data.get('id') or '').strip()
    name = str(data.get('name') or '').strip()
    if not pid or not name:
        return jsonify({'ok': False, 'error': 'id and name required'}), 400
    if Product.query.get(pid):
        return jsonify({'ok': False, 'error': 'Product already exists'}), 409
    p = Product(
        id=pid,
        name=name,
        description=str(data.get('description') or ''),
        price_cents=int(data.get('price_cents') or 500),
        stripe_price_id=str(data.get('stripe_price_id') or '') or None,
        badge=str(data.get('badge') or '') or None,
        sort_order=int(data.get('sort_order') or 0),
        download_ref=str(data.get('download_ref') or '') or None,
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'ok': True, 'product': p.to_dict()}), 201


@web_bp.route('/api/admin/products/<product_id>', methods=['PATCH'])
def admin_update_product(product_id):
    err, data = _require_admin_token()
    if err:
        return err
    p = Product.query.get(product_id)
    if not p:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    for field in ('name', 'description', 'price_cents', 'stripe_price_id',
                  'is_active', 'sort_order', 'download_ref', 'badge', 'bundle_items'):
        if field in data:
            setattr(p, field, data[field])
    db.session.commit()
    return jsonify({'ok': True, 'product': p.to_dict()}), 200


@web_bp.route('/api/admin/entitlements/grant', methods=['POST'])
def admin_grant_entitlement():
    """Manually grant a standalone product entitlement by license key."""
    err, data = _require_admin_token()
    if err:
        return err
    raw_key = str(data.get('license_key') or '').strip()
    product_id = str(data.get('product_id') or '').strip()
    if not raw_key or not product_id:
        return jsonify({'ok': False, 'error': 'license_key and product_id required'}), 400

    from auth.routes import _lookup_license_by_key
    lic = _lookup_license_by_key(raw_key)
    if not lic:
        return jsonify({'ok': False, 'error': 'License not found'}), 404

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'ok': False, 'error': 'Product not found'}), 404

    existing = UserEntitlement.query.filter_by(
        license_key_hash=lic.key_hash, product_id=product_id
    ).first()
    if existing:
        return jsonify({'ok': True, 'message': 'Already granted', 'granted_at': existing.granted_at.isoformat()}), 200

    ent = UserEntitlement(
        license_key_hash=lic.key_hash,
        product_id=product_id,
        charged_cents=0,
    )
    db.session.add(ent)
    db.session.commit()
    audit_event('admin.entitlement.grant', product_id=product_id, license_id=lic.id)
    return jsonify({'ok': True, 'message': 'Entitlement granted'}), 201


@web_bp.route('/api/admin/entitlements/revoke', methods=['POST'])
def admin_revoke_entitlement():
    err, data = _require_admin_token()
    if err:
        return err
    raw_key = str(data.get('license_key') or '').strip()
    product_id = str(data.get('product_id') or '').strip()
    if not raw_key or not product_id:
        return jsonify({'ok': False, 'error': 'license_key and product_id required'}), 400

    from auth.routes import _lookup_license_by_key
    lic = _lookup_license_by_key(raw_key)
    if not lic:
        return jsonify({'ok': False, 'error': 'License not found'}), 404

    ent = UserEntitlement.query.filter_by(
        license_key_hash=lic.key_hash, product_id=product_id
    ).first()
    if not ent:
        return jsonify({'ok': False, 'error': 'Entitlement not found'}), 404

    db.session.delete(ent)
    db.session.commit()
    audit_event('admin.entitlement.revoke', product_id=product_id, license_id=lic.id)
    return jsonify({'ok': True, 'message': 'Entitlement revoked'}), 200


# â”€â”€ Tauri auto-updater endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Cache: (version, url, signature, notes, fetched_at_ms)
_updater_cache: dict = {}
_UPDATER_CACHE_TTL_MS = 60_000  # 60 seconds


def _fetch_updater_data() -> dict | None:
    """
    Query the latest GitHub release to get updater metadata.
    Looks for a .nsis.zip asset and its matching .sig file.
    Falls back to Fly secrets (TAURI_UPDATE_*) if GitHub is unavailable or not configured.
    Results are cached for 60 seconds.
    """
    import os as _os

    now = _unix_ms()
    cached = _updater_cache.get('data')
    if cached and (now - int(_updater_cache.get('ts_ms') or 0)) < _UPDATER_CACHE_TTL_MS:
        return cached  # type: ignore[return-value]

    # Try GitHub first (dynamic â€” no Fly secrets needed after each release)
    if _github_release_ready():
        try:
            repo = _release_repo()
            req = _github_api_request(f'https://api.github.com/repos/{repo}/releases/latest')
            payload = _json_from_url(req)
            assets = payload.get('assets') or []
            version = str(payload.get('tag_name') or '').strip()
            notes = str(payload.get('body') or '').strip()[:2000]

            # Find the .nsis.zip update bundle and its .sig
            zip_asset = next(
                (a for a in assets if str(a.get('name', '')).lower().endswith('.nsis.zip')),
                None
            )
            sig_asset = next(
                (a for a in assets if str(a.get('name', '')).lower().endswith('.nsis.zip.sig')),
                None
            )

            if zip_asset and sig_asset and version:
                # Fetch signature content (it's a small text file)
                sig_req = _github_api_request(
                    sig_asset.get('url', ''),
                    accept='application/octet-stream',
                )
                sig_content = urlopen(sig_req, timeout=10).read().decode('utf-8').strip()  # type: ignore[arg-type]

                # Resolve the zip download URL.
                # For private repos the direct github.com/releases/download/ URL requires
                # authentication, so the Tauri updater (which sends no auth headers) gets a
                # 404. Instead we ask the GitHub API for the asset with
                # Accept: application/octet-stream â€” GitHub responds with a 302 redirect to
                # a temporary S3 presigned URL that is publicly accessible (~5 min TTL).
                import urllib.request as _ureq
                import urllib.error as _uerr

                class _NoRedirect(_ureq.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
                        return None

                zip_url = ''
                try:
                    _zip_req = _github_api_request(
                        zip_asset.get('url', ''),
                        accept='application/octet-stream',
                    )
                    _opener = _ureq.build_opener(_NoRedirect)
                    _opener.open(_zip_req, timeout=10)
                except _uerr.HTTPError as _redir_err:
                    if _redir_err.code in (301, 302, 303, 307, 308):
                        zip_url = _redir_err.headers.get('Location', '')
                except Exception:
                    pass

                # Fallback to direct URL if redirect capture failed
                if not zip_url:
                    zip_name = str(zip_asset.get('name', ''))
                    zip_url = f'https://github.com/{repo}/releases/download/{version}/{zip_name}'

                data = {
                    'version': version,
                    'url': zip_url,
                    'signature': sig_content,
                    'notes': notes or f'Update to {version}',
                }
                _updater_cache['data'] = data
                _updater_cache['ts_ms'] = now
                return data
        except Exception:
            pass  # Fall through to env-var fallback

    # Fallback: read from Fly secrets / environment (legacy path)
    latest = str(current_app.config.get('TAURI_UPDATE_VERSION') or _os.environ.get('TAURI_UPDATE_VERSION', '')).strip()
    url = str(current_app.config.get('TAURI_UPDATE_URL') or _os.environ.get('TAURI_UPDATE_URL', '')).strip()
    sig = str(current_app.config.get('TAURI_UPDATE_SIGNATURE') or _os.environ.get('TAURI_UPDATE_SIGNATURE', '')).strip()
    notes_env = str(current_app.config.get('TAURI_UPDATE_NOTES') or _os.environ.get('TAURI_UPDATE_NOTES', '')).strip()

    if latest and url:
        data = {
            'version': latest,
            'url': url,
            'signature': sig,
            'notes': notes_env or f'Update to {latest}',
        }
        _updater_cache['data'] = data
        _updater_cache['ts_ms'] = now
        return data

    return None


@web_bp.route('/api/updater/<target>/<arch>/<current_version>', methods=['GET'])
def tauri_updater(target: str, arch: str, current_version: str):
    """Tauri v2 updater endpoint. Returns 204 if up-to-date, or JSON manifest if update available.

    Reads update metadata dynamically from the latest GitHub release (looks for
    .nsis.zip and .nsis.zip.sig assets). Falls back to TAURI_UPDATE_* Fly secrets
    if GitHub is not configured or unavailable.
    """
    update = _fetch_updater_data()
    if not update:
        return '', 204

    # Proper semver compare â€” string comparison breaks on e.g. "1.2.9" vs "1.2.10"
    def _parse_ver(v: str):
        parts = v.lstrip('v').split('.')
        try:
            return tuple(int(x) for x in parts[:3])
        except ValueError:
            return (0, 0, 0)

    cv = _parse_ver(current_version)
    lv = _parse_ver(str(update.get('version', '')))
    if lv == (0, 0, 0) or cv >= lv:
        return '', 204

    body: dict = {
        'version': update['version'],
        'url': update['url'],
        'signature': update['signature'],
        'notes': update.get('notes', f"Update to {update['version']}"),
        'pub_date': update.get('pub_date', ''),
    }
    return jsonify(body), 200
