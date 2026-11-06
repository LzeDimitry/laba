"""Тести моделі керування доступом (ЛР5)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from suc.authz import AccessDenied, Guard, Permission, Principal, Role
from suc.authz.model import ROLE_PERMISSIONS, STABLE_CHANNEL


def P(role: Role, mfa: bool = True) -> Principal:
    return Principal("u-test", role, mfa_passed=mfa)


# ---------- матриця ролей ----------
@pytest.mark.parametrize("role,permission,expected", [
    (Role.VIEWER, Permission.RELEASE_READ, True),
    (Role.VIEWER, Permission.RELEASE_PUBLISH, False),
    (Role.VIEWER, Permission.AUDIT_READ, False),
    (Role.AUDITOR, Permission.AUDIT_READ, True),
    (Role.AUDITOR, Permission.RELEASE_PUBLISH, False),
    (Role.RELEASE_MANAGER, Permission.RELEASE_PUBLISH, True),
    (Role.RELEASE_MANAGER, Permission.USER_MANAGE, False),
    (Role.ADMIN, Permission.USER_MANAGE, True),
    (Role.ADMIN, Permission.CHANNEL_MANAGE, True),
])
def test_role_matrix(role, permission, expected):
    decision = Guard().policy.evaluate(P(role), permission, {})
    assert decision.allowed is expected


def test_admin_has_every_permission():
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)


# ---------- ABAC-умови ----------
def test_publish_requires_mfa():
    guard = Guard()
    assert guard.check(P(Role.RELEASE_MANAGER, mfa=True), Permission.RELEASE_PUBLISH, {"channel": "beta"}).allowed
    assert not guard.check(P(Role.RELEASE_MANAGER, mfa=False), Permission.RELEASE_PUBLISH, {"channel": "beta"}).allowed


def test_stable_requires_admin():
    guard = Guard()
    resource = {"channel": STABLE_CHANNEL, "approved": True}
    assert not guard.check(P(Role.RELEASE_MANAGER), Permission.RELEASE_PUBLISH, resource).allowed
    assert guard.check(P(Role.ADMIN), Permission.RELEASE_PUBLISH, resource).allowed


def test_stable_requires_approval():
    guard = Guard()
    resource = {"channel": STABLE_CHANNEL}
    decision = guard.check(P(Role.ADMIN), Permission.RELEASE_PUBLISH, resource)
    assert not decision.allowed
    assert "схвалення" in decision.reason


def test_beta_channel_does_not_require_approval():
    assert Guard().check(P(Role.RELEASE_MANAGER), Permission.RELEASE_PUBLISH, {"channel": "beta"}).allowed


def test_auditor_cannot_read_foreign_tenant():
    guard = Guard()
    assert guard.check(P(Role.AUDITOR), Permission.AUDIT_READ, {"tenant": "t1", "actor_tenant": "t1"}).allowed
    assert not guard.check(P(Role.AUDITOR), Permission.AUDIT_READ, {"tenant": "t2", "actor_tenant": "t1"}).allowed


def test_user_manage_cannot_target_admin():
    assert not Guard().check(P(Role.ADMIN), Permission.USER_MANAGE, {"target_role": Role.ADMIN}).allowed


# ---------- guard ----------
def test_enforce_raises_access_denied():
    with pytest.raises(AccessDenied) as exc:
        Guard().enforce(P(Role.VIEWER), Permission.RELEASE_PUBLISH, {"channel": "beta"})
    assert exc.value.permission is Permission.RELEASE_PUBLISH


def test_every_check_is_audited():
    guard = Guard()
    guard.check(P(Role.VIEWER), Permission.RELEASE_READ)
    guard.check(P(Role.VIEWER), Permission.USER_MANAGE)
    assert len(guard.audit) == 2
    assert [r.allowed for r in guard.audit] == [True, False]


def test_protected_function_is_not_called_on_deny():
    guard = Guard()
    calls = []

    @guard_require(guard)
    def publish(principal, channel):
        calls.append(channel)
        return "published"

    with pytest.raises(AccessDenied):
        publish(P(Role.VIEWER), "beta")
    assert calls == []


def guard_require(guard):
    from suc.authz import require

    return require(guard, Permission.RELEASE_PUBLISH, lambda channel: {"channel": channel})
