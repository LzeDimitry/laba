"""Тести контролю цілісності та автентичності (ЛР7)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from suc.integrity import (
    flip_bit,
    generate_hmac_key,
    hamming_distance_hex,
    hmac_sha256,
    sha256_hex,
    verify_hmac,
)


def test_sha256_is_deterministic():
    assert sha256_hex(b"data") == sha256_hex(b"data")


def test_sha256_avalanche_effect():
    a = sha256_hex(b"2026_KBZI-24-2_Tovt_Rastislav_variant:01")
    b = sha256_hex(b"2026_KBZI-24-2_Tovt_Rastislav_variant:02")
    assert a != b
    # будь-яка зміна одного символу змінює приблизно половину бітів
    assert hamming_distance_hex(a, b) > 80


def test_hmac_accepts_original_message():
    key = generate_hmac_key()
    mac = hmac_sha256(key, b"payload")
    assert verify_hmac(key, b"payload", mac)


def test_hmac_rejects_modified_message():
    key = generate_hmac_key()
    mac = hmac_sha256(key, b"payload")
    assert not verify_hmac(key, b"payloaD", mac)


def test_hmac_rejects_modified_key():
    key = generate_hmac_key()
    mac = hmac_sha256(key, b"payload")
    assert not verify_hmac(flip_bit(key), b"payload", mac)


def test_single_bit_key_change_changes_mac():
    key = generate_hmac_key()
    mac1 = hmac_sha256(key, b"payload")
    mac2 = hmac_sha256(flip_bit(key), b"payload")
    assert mac1 != mac2
    assert hamming_distance_hex(mac1, mac2) > 80


def test_hmac_differs_from_plain_hash():
    key = generate_hmac_key()
    assert hmac_sha256(key, b"payload") != sha256_hex(b"payload")


def test_hamming_distance_self_is_zero():
    a = sha256_hex(b"x")
    assert hamming_distance_hex(a, a) == 0
