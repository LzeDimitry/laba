"""Тести механізмів автентифікації (ЛР4)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from suc.auth.mfa import generate_secret, totp_at, verify_totp
from suc.auth.passwords import BCRYPT_MAX_BYTES, hash_password, prepare_password, verify_password
from suc.auth.sessions import SessionStore
from suc.auth.users import UserStore


# ---------- паролі ----------
def test_hash_and_verify_roundtrip():
    hashed = hash_password("S3cret-pass", cost=12)
    assert hashed.startswith("$2b$12$")
    assert verify_password("S3cret-pass", hashed)
    assert not verify_password("S3cret-pas", hashed)


def test_hash_is_salted():
    assert hash_password("same", cost=12) != hash_password("same", cost=12)


def test_cost_below_policy_rejected():
    with pytest.raises(ValueError):
        hash_password("x", cost=10)


def test_long_input_truncated_at_72_bytes():
    long_password = "a" * 100
    assert len(prepare_password(long_password)) == BCRYPT_MAX_BYTES
    hashed = hash_password(long_password, cost=12)
    # все, що після 72-го байта, не впливає на перевірку
    assert verify_password("a" * 72, hashed)
    assert verify_password("a" * 100, hashed)


# ---------- користувачі ----------
def test_authenticate_and_lockout(tmp_path):
    store = UserStore(tmp_path / "users.json", cost=12)
    store.create("op@example.com", "correct-horse", role="release_manager")

    assert store.authenticate("op@example.com", "wrong") is None
    user = store.authenticate("op@example.com", "correct-horse")
    assert user is not None
    assert user.role == "release_manager"

    for _ in range(UserStore.MAX_FAILED_ATTEMPTS):
        store.authenticate("op@example.com", "wrong")
    assert store.find_by_email("op@example.com").locked
    assert store.authenticate("op@example.com", "correct-horse") is None


def test_unknown_user_returns_none(tmp_path):
    store = UserStore(tmp_path / "users.json")
    assert store.authenticate("nobody@example.com", "x") is None


def test_email_is_case_insensitive(tmp_path):
    store = UserStore(tmp_path / "users.json")
    store.create("Op@Example.COM", "pw-123456789")
    assert store.authenticate("op@example.com", "pw-123456789") is not None


# ---------- сесії ----------
def test_session_lifecycle():
    store = SessionStore()
    token = store.create("user-1")
    assert store.get(token) is not None
    assert store.active_count() == 1
    assert store.revoke(token)
    assert store.get(token) is None


def test_session_rotation_invalidates_old_token():
    store = SessionStore()
    token = store.create("user-1")
    new_token = store.rotate(token)
    assert new_token and new_token != token
    assert store.get(token) is None
    assert store.get(new_token) is not None


def test_revoke_all_for_user():
    store = SessionStore()
    store.create("user-1")
    store.create("user-1")
    store.create("user-2")
    assert store.revoke_all("user-1") == 2
    assert store.active_count() == 1


# ---------- MFA ----------
def test_totp_current_code_accepted():
    secret = generate_secret()
    assert verify_totp(secret, totp_at(secret))


def test_totp_expired_code_rejected():
    secret = generate_secret()
    assert not verify_totp(secret, totp_at(secret, timestamp=1_000_000_000))


def test_totp_malformed_code_rejected():
    secret = generate_secret()
    assert not verify_totp(secret, "abcdef")
    assert not verify_totp(secret, "12345")
