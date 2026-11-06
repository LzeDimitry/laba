"""Тести симетричного криптографічного захисту (ЛР6)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from suc.crypto import (
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_iv,
    generate_key,
    tamper,
)


def test_ctr_roundtrip():
    key, iv = generate_key(), generate_iv()
    data = "2026_KBZI-24-2_Tovt_Rastislav_варіант:01".encode()
    assert aes_ctr_decrypt(key, iv, aes_ctr_encrypt(key, iv, data)) == data


def test_ctr_is_stream_and_gamma_is_reusable():
    key, iv = generate_key(), generate_iv()
    a, b = b"AAAAAAAAAA", b"BBBBBBBBBB"
    ca, cb = aes_ctr_encrypt(key, iv, a), aes_ctr_encrypt(key, iv, b)
    gamma = bytes(x ^ y for x, y in zip(ca, a))
    # та сама гама дає валідний шифротекст для іншого тексту
    forged = bytes(x ^ y for x, y in zip(gamma, b))
    assert forged == cb


def test_ctr_different_iv_gives_different_ciphertext():
    key = generate_key()
    data = b"same plaintext"
    assert aes_ctr_encrypt(key, generate_iv(), data) != aes_ctr_encrypt(key, generate_iv(), data)


def test_ctr_rejects_bad_iv():
    with pytest.raises(ValueError):
        aes_ctr_encrypt(generate_key(), b"short", b"data")


def test_gcm_roundtrip():
    key = generate_key()
    sealed = aes_gcm_encrypt(key, b"payload", aad=b"header")
    assert aes_gcm_decrypt(key, sealed.nonce, sealed.ciphertext, aad=b"header") == b"payload"


def test_gcm_detects_tampering():
    key = generate_key()
    sealed = aes_gcm_encrypt(key, b"payload")
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, sealed.nonce, tamper(sealed.ciphertext))


def test_gcm_detects_aad_change():
    key = generate_key()
    sealed = aes_gcm_encrypt(key, b"payload", aad=b"v1")
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, sealed.nonce, sealed.ciphertext, aad=b"v2")


def test_gcm_nonce_is_unique():
    key = generate_key()
    nonces = {aes_gcm_encrypt(key, b"x").nonce for _ in range(50)}
    assert len(nonces) == 50
