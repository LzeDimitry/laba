"""Ліцензування та захист від несанкціонованого копіювання (ЛР8).

Ліцензія — це JSON-документ, підписаний приватним ключем розробника
(RSA-PSS + SHA-256). Клієнт перевіряє підпис вбудованим відкритим ключем,
тому підробка ліцензії без приватного ключа неможлива.

Підпис, а не MAC: перевіряюча сторона (клієнт) не повинна мати секрету,
інакше будь-який користувач зміг би сформувати власну ліцензію.
Підпис, а не MDC (звичайний хеш): хеш можна перерахувати разом із
модифікованим вмістом.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REQUIRED_FIELDS = ("product_id", "license_owner", "expires_at", "features", "license_id")


class LicenseError(Exception):
    pass


@dataclass
class License:
    product_id: str
    license_owner: str
    expires_at: str
    features: list[str] = field(default_factory=list)
    license_id: str = ""

    def to_bytes(self) -> bytes:
        """Канонічне подання: саме ці байти підписуються і перевіряються."""
        payload = {
            "product_id": self.product_id,
            "license_owner": self.license_owner,
            "expires_at": self.expires_at,
            "features": sorted(self.features),
            "license_id": self.license_id,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "License":
        data: dict[str, Any] = json.loads(raw.decode("utf-8"))
        missing = [f for f in REQUIRED_FIELDS if f not in data]
        if missing:
            raise LicenseError(f"license missing fields: {', '.join(missing)}")
        return cls(
            product_id=data["product_id"],
            license_owner=data["license_owner"],
            expires_at=data["expires_at"],
            features=list(data["features"]),
            license_id=data["license_id"],
        )

    def is_expired(self, today: date | None = None) -> bool:
        return date.fromisoformat(self.expires_at) < (today or date.today())

    def has_feature(self, feature: str) -> bool:
        return feature in self.features


# ---------- підпис ----------
def generate_keypair(bits: int = 3072) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def sign_license(license: License, private_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.sign(license.to_bytes(), _pss(), hashes.SHA256())


def verify_license(license: License, signature: bytes, public_pem: bytes) -> bool:
    key = serialization.load_pem_public_key(public_pem)
    try:
        key.verify(signature, license.to_bytes(), _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def verify_license_file(raw: bytes, signature: bytes, public_pem: bytes) -> tuple[bool, License | None]:
    """Перевіряє підпис і повертає розібрану ліцензію лише після успіху."""
    try:
        license = License.from_bytes(raw)
    except (json.JSONDecodeError, LicenseError):
        return False, None
    if not verify_license(license, signature, public_pem):
        return False, None
    return True, license
