"""Контроль цілісності та автентичності (ЛР7).

Три рівні захисту:

* **SHA-256** — виявляє випадкову модифікацію, але не захищає від
  підміни, якщо зловмисник може змінити і дані, і еталонний хеш;
* **HMAC-SHA256** — додає секретний ключ, тому підміна без ключа неможлива;
* **AES-GCM** — одночасно забезпечує конфіденційність і цілісність.
"""

from __future__ import annotations

import hashlib
import hmac
import os

HMAC_KEY_BYTES = 32


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, data: bytes, expected: str) -> bool:
    """Порівняння у сталий час (захист від timing-атак)."""
    return hmac.compare_digest(hmac_sha256(key, data), expected)


def generate_hmac_key() -> bytes:
    return os.urandom(HMAC_KEY_BYTES)


def flip_bit(data: bytes, bit_index: int = 0) -> bytes:
    """Змінює один біт у копії даних."""
    buf = bytearray(data)
    buf[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(buf)


def hamming_distance_hex(a: str, b: str) -> int:
    """Кількість різних бітів між двома hex-рядками."""
    if len(a) != len(b):
        raise ValueError("hex strings must have equal length")
    return sum(bin(x ^ y).count("1") for x, y in zip(bytes.fromhex(a), bytes.fromhex(b)))


def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("inputs must have equal length")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
