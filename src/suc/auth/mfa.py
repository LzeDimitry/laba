"""Другий фактор автентифікації — TOTP (RFC 6238).

Реалізовано без зовнішніх залежностей: HMAC-SHA1, крок 30 секунд,
6 цифр, вікно перевірки ±1 інтервал для компенсації розбіжності годинників.

Секрет зберігається у сховищі користувача та ніколи не журналюється
(див. privacy_policy.md, розділ 8).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

DIGITS = 6
STEP = 30
WINDOW = 1


def generate_secret(length: int = 20) -> str:
    """Генерує base32-секрет для TOTP."""
    return base64.b32encode(secrets.token_bytes(length)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = DIGITS) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_at(secret: str, timestamp: float | None = None) -> str:
    counter = int((timestamp or time.time()) // STEP)
    return _hotp(secret, counter)


totp_now = totp_at  # зручний псевдонім


def verify_totp(secret: str, code: str, timestamp: float | None = None,
                window: int = WINDOW) -> bool:
    """Перевіряє код із вікном припустимого відхилення."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return False
    counter = int((timestamp or time.time()) // STEP)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, counter + drift), code):
            return True
    return False
