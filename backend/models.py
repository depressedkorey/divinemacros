import json
import secrets
from datetime import datetime, timezone
from database import db


class License(db.Model):
    __tablename__ = 'licenses'

    id = db.Column(db.Integer, primary_key=True)

    # Normalized 20-char key (stored for admin lookups only; prefer key_hash)
    key = db.Column(db.String(32), unique=True, nullable=False)

    # SHA-256 hex of the normalized key - used for fast constant-time lookup
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # 32 random bytes - the per-user AES encryption key (stored as hex)
    user_enc_key = db.Column(db.String(64), nullable=False)

    # 32 hex chars - mixed into JWT signing to make each user's tokens unique
    user_salt = db.Column(db.String(64), nullable=False)

    # SHA-256 hex of the device HWID bound to this license
    hwid_hash = db.Column(db.String(64), nullable=True)

    # Rotated whenever a new authenticated session is issued.
    session_nonce = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))

    # How many times the HWID binding has been changed
    hwid_change_count = db.Column(db.Integer, nullable=False, default=0)

    # "monthly" or "lifetime"
    tier = db.Column(db.String(16), nullable=False, default='monthly')

    is_revoked = db.Column(db.Boolean, nullable=False, default=False)

    activated_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_validated = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    # Indexed affiliate/referral code for fast lookups
    affiliate_code = db.Column(db.String(64), nullable=True, index=True)

    # JSON string for anomaly / audit metadata
    _metadata = db.Column('metadata', db.Text, nullable=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def extra_metadata(self) -> dict:
        if self._metadata:
            try:
                return json.loads(self._metadata)
            except (ValueError, TypeError):
                return {}
        return {}

    @extra_metadata.setter
    def extra_metadata(self, value: dict):
        self._metadata = json.dumps(value)

    def is_active(self) -> bool:
        """Return True when the license can be used right now."""
        if self.is_revoked:
            return False
        if self.expires_at is not None:
            now = datetime.now(timezone.utc)
            exp = self.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                return False
        return True

    def __repr__(self) -> str:
        return f'<License id={self.id} tier={self.tier} revoked={self.is_revoked}>'


class Product(db.Model):
    __tablename__ = 'products'

    # Slug ID, e.g. "zenith-single-anchor"
    id              = db.Column(db.String(64), primary_key=True)
    name            = db.Column(db.String(128), nullable=False)
    description     = db.Column(db.Text, default='')
    price_cents     = db.Column(db.Integer, nullable=False)         # 500 = $5.00
    stripe_price_id = db.Column(db.String(128), nullable=True)      # Stripe Price ID
    is_active       = db.Column(db.Boolean, nullable=False, default=True)
    sort_order      = db.Column(db.Integer, nullable=False, default=0)
    # GitHub release asset name or direct URL for the download
    download_ref    = db.Column(db.String(256), nullable=True)
    badge           = db.Column(db.String(8), nullable=True)        # e.g. "SA"
    # Comma-separated product IDs included in this bundle (empty = not a bundle)
    bundle_items    = db.Column(db.String(512), nullable=True)
    created_at      = db.Column(db.DateTime, nullable=False,
                                default=lambda: datetime.now(timezone.utc))

    entitlements    = db.relationship('UserEntitlement', back_populates='product',
                                      lazy='dynamic')

    def to_dict(self) -> dict:
        items = [x.strip() for x in (self.bundle_items or '').split(',') if x.strip()]
        return {
            'id':           self.id,
            'name':         self.name,
            'description':  self.description,
            'price_cents':  self.price_cents,
            'badge':        self.badge or self.id.split('-')[-1].upper()[:3],
            'is_active':    self.is_active,
            'sort_order':   self.sort_order,
            'bundle_items': items,
            'download_ref': self.download_ref or '',
        }

    def __repr__(self) -> str:
        return f'<Product id={self.id} price={self.price_cents}>'


class ClientNotification(db.Model):
    __tablename__ = 'client_notifications'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(
        db.String(32), unique=True, nullable=False, index=True,
        default=lambda: secrets.token_hex(12),
    )
    audience = db.Column(db.String(16), nullable=False, default='all', index=True)
    discord_id = db.Column(db.String(32), nullable=True, index=True)
    kind = db.Column(db.String(16), nullable=False, default='info')
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    action_label = db.Column(db.String(40), nullable=True)
    action_url = db.Column(db.String(500), nullable=True)
    created_by = db.Column(db.String(64), nullable=False, default='system')
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=lambda: datetime.now(timezone.utc), index=True,
    )
    expires_at = db.Column(db.DateTime, nullable=True, index=True)

    def to_dict(self) -> dict:
        def iso(value):
            if value is None:
                return None
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()

        return {
            'id': self.public_id,
            'audience': self.audience,
            'kind': self.kind,
            'title': self.title,
            'message': self.message,
            'actionLabel': self.action_label or '',
            'actionUrl': self.action_url or '',
            'createdBy': self.created_by,
            'createdAt': iso(self.created_at),
            'expiresAt': iso(self.expires_at),
        }


class ClientFeatureLock(db.Model):
    __tablename__ = 'client_feature_locks'

    category = db.Column(db.String(48), primary_key=True)
    is_locked = db.Column(db.Boolean, nullable=False, default=True, index=True)
    reason = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.String(64), nullable=False, default='system')
    updated_at = db.Column(
        db.DateTime, nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        updated_at = self.updated_at
        if updated_at is not None and updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
        return {
            'category': self.category,
            'locked': bool(self.is_locked),
            'reason': self.reason or '',
            'updatedBy': self.updated_by,
            'updatedAt': updated_at.isoformat() if updated_at else None,
        }


class UserEntitlement(db.Model):
    __tablename__ = 'user_entitlements'

    id               = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Links to the license that owns this entitlement
    license_key_hash = db.Column(db.String(64), db.ForeignKey('licenses.key_hash'),
                                 nullable=False, index=True)
    product_id       = db.Column(db.String(64), db.ForeignKey('products.id'),
                                 nullable=False)
    stripe_ref       = db.Column(db.String(256), nullable=True)     # idempotency
    charged_cents    = db.Column(db.Integer, nullable=False, default=0)
    granted_at       = db.Column(db.DateTime, nullable=False,
                                 default=lambda: datetime.now(timezone.utc))

    product = db.relationship('Product', back_populates='entitlements')

    __table_args__ = (
        db.UniqueConstraint('license_key_hash', 'product_id', name='uq_entitlement'),
    )

    def __repr__(self) -> str:
        return f'<UserEntitlement license_hash={self.license_key_hash[:8]}… product={self.product_id}>'
