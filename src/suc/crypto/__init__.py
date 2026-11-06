"""Симетричний криптографічний захист (ЛР6).

Модуль надає два режими:

* ``aes_gcm_encrypt`` / ``aes_gcm_decrypt`` — автентифіковане шифрування,
  яке використовується для захисту даних проєкту (SR-16);
* ``aes_ctr_encrypt`` / ``aes_ctr_decrypt`` — потоковий режим, який
  використовується лише в навчальних експериментах, оскільки не забезпечує
  автентичності.

Ключі ніколи не генеруються з пароля користувача без KDF: для паролів
використовується bcrypt (див. ``suc.auth.passwords``), а для симетричних
ключів — криптографічно стійкий генератор.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32   # AES-256
IV_BYTES = 16    # блок AES; для GCM — 12 байт nonce
NONCE_BYTES = 12


def generate_key() -> bytes:
    return os.urandom(KEY_BYTES)


def generate_iv() -> bytes:
    return os.urandom(IV_BYTES)


# ---------- AES-CTR (навчальний режим) ----------
def aes_ctr_xor(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Шифрує або розшифровує дані в режимі CTR (операція симетрична)."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    if len(iv) != IV_BYTES:
        raise ValueError("CTR IV must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    op = cipher.encryptor()
    return op.update(data) + op.finalize()


aes_ctr_encrypt = aes_ctr_xor
aes_ctr_decrypt = aes_ctr_xor


# ---------- AES-GCM (робочий режим) ----------
@dataclass(frozen=True)
class Sealed:
    nonce: bytes
    ciphertext: bytes
    tag_included: bool = True


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> Sealed:
    """Шифрує дані; тег автентифікації дописується до шифротексту."""
    nonce = os.urandom(NONCE_BYTES)
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Sealed(nonce=nonce, ciphertext=blob)


def aes_gcm_decrypt(key: bytes, nonce: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    """Розшифровує дані; при підміні байта виникає InvalidTag."""
    return AESGCM(key).decrypt(nonce, blob, aad)


def tamper(blob: bytes, index: int = 0) -> bytes:
    """Змінює один байт шифротексту (для негативних тестів)."""
    data = bytearray(blob)
    data[index] ^= 0x01
    return bytes(data)
