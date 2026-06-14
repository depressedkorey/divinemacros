import base64
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _clean(value: object) -> str:
    return str(value or '').replace('|', '%7C')


def auth_response_material(kind: str, fields: Iterable[object]) -> bytes:
    parts = ['divine-auth-v1', kind]
    parts.extend(_clean(value) for value in fields)
    return '|'.join(parts).encode('utf-8')


def sign_auth_response(kind: str, fields: Iterable[object], private_key_b64: str) -> str:
    raw = base64.b64decode(str(private_key_b64 or '').strip(), validate=True)
    if len(raw) != 32:
        raise ValueError('AUTH_RESPONSE_SIGNING_KEY must be a base64 Ed25519 private key')
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    signature = private_key.sign(auth_response_material(kind, fields))
    return base64.b64encode(signature).decode('ascii')
