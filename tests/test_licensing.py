"""Тести ліцензування (ЛР8)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from suc.licensing import (
    License,
    generate_keypair,
    sign_license,
    verify_license,
    verify_license_file,
)


@pytest.fixture(scope="module")
def keys():
    return generate_keypair(2048)  # швидше для тестів


@pytest.fixture
def license_obj():
    return License(
        product_id="secure-update-client",
        license_owner="Test Owner",
        expires_at="2027-06-30",
        features=["release.read", "release.publish"],
        license_id="SUC-TEST-0001",
    )


def test_sign_and_verify(keys, license_obj):
    private, public = keys
    signature = sign_license(license_obj, private)
    assert verify_license(license_obj, signature, public)


def test_tampered_license_rejected(keys, license_obj):
    private, public = keys
    signature = sign_license(license_obj, private)
    license_obj.expires_at = "2030-12-31"
    assert not verify_license(license_obj, signature, public)


def test_order_of_features_does_not_matter(keys):
    private, public = keys
    a = License("p", "o", "2027-01-01", ["b", "a"], "id")
    b = License("p", "o", "2027-01-01", ["a", "b"], "id")
    signature = sign_license(a, private)
    assert verify_license(b, signature, public)


def test_wrong_key_rejected(keys, license_obj):
    private, _ = keys
    _, other_public = generate_keypair(2048)
    signature = sign_license(license_obj, private)
    assert not verify_license(license_obj, signature, other_public)


def test_expiration():
    lic = License("p", "o", "2020-01-01", [], "id")
    assert lic.is_expired()
    assert not License("p", "o", "2999-01-01", [], "id").is_expired()


def test_feature_lookup(license_obj):
    assert license_obj.has_feature("release.publish")
    assert not license_obj.has_feature("channel.manage")


def test_missing_field_rejected():
    raw = json.dumps({"product_id": "p"}).encode()
    ok, lic = verify_license_file(raw, b"sig", b"key")
    assert not ok and lic is None


def test_invalid_json_rejected():
    ok, lic = verify_license_file(b"{not json", b"sig", b"key")
    assert not ok and lic is None
