#!/usr/bin/env python3
"""ЛР5: демонстрація моделі керування доступом.

Друкує матрицю «роль × дозвіл» та журнал перевірок для дозволених і
заборонених сценаріїв.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from suc.authz import AccessDenied, Guard, Permission, Principal, Role
from suc.authz.model import ROLE_PERMISSIONS, STABLE_CHANNEL

ROLE_ORDER = [Role.ADMIN, Role.RELEASE_MANAGER, Role.AUDITOR, Role.VIEWER]
PERM_ORDER = list(Permission)


SHORT = {
    "release.read": "r",
    "release.publish": "p",
    "release.sign": "s",
    "channel.manage": "ch",
    "user.manage": "u",
    "audit.read": "a",
    "license.manage": "lic",
}


def print_matrix() -> None:
    head = f"{'Роль':<17}" + "".join(f"{SHORT[p.value]:>5}" for p in PERM_ORDER)
    print(head)
    print("-" * len(head))
    for role in ROLE_ORDER:
        row = f"{role.value:<17}"
        for perm in PERM_ORDER:
            row += f"{'так' if perm in ROLE_PERMISSIONS[role] else '-':>5}"
        print(row)
    print()
    print("  r — release.read   p — release.publish   s — release.sign   ch — channel.manage")
    print("  u — user.manage    a — audit.read        lic — license.manage")


SCENARIOS = [
    ("viewer читає релізи", Principal("u1", Role.VIEWER), Permission.RELEASE_READ, {}),
    ("viewer публікує реліз", Principal("u1", Role.VIEWER), Permission.RELEASE_PUBLISH, {"channel": "beta"}),
    ("release_manager публікує у beta", Principal("u2", Role.RELEASE_MANAGER, True), Permission.RELEASE_PUBLISH, {"channel": "beta"}),
    ("release_manager публікує у beta без MFA", Principal("u2", Role.RELEASE_MANAGER, False), Permission.RELEASE_PUBLISH, {"channel": "beta"}),
    ("release_manager публікує у stable", Principal("u2", Role.RELEASE_MANAGER, True), Permission.RELEASE_PUBLISH, {"channel": STABLE_CHANNEL, "approved": True}),
    ("admin публікує у stable без схвалення", Principal("u3", Role.ADMIN, True), Permission.RELEASE_PUBLISH, {"channel": STABLE_CHANNEL}),
    ("admin публікує у stable зі схваленням", Principal("u3", Role.ADMIN, True), Permission.RELEASE_PUBLISH, {"channel": STABLE_CHANNEL, "approved": True}),
    ("auditor читає журнал", Principal("u4", Role.AUDITOR), Permission.AUDIT_READ, {"tenant": "t1", "actor_tenant": "t1"}),
    ("auditor читає чужий журнал", Principal("u4", Role.AUDITOR), Permission.AUDIT_READ, {"tenant": "t2", "actor_tenant": "t1"}),
    ("release_manager керує користувачами", Principal("u2", Role.RELEASE_MANAGER, True), Permission.USER_MANAGE, {}),
    ("admin створює адміністратора", Principal("u3", Role.ADMIN, True), Permission.USER_MANAGE, {"target_role": Role.ADMIN}),
    ("admin керує користувачами", Principal("u3", Role.ADMIN, True), Permission.USER_MANAGE, {"target_role": Role.AUDITOR}),
]


def main() -> None:
    guard = Guard()

    print("Матриця дозволів роль × операція")
    print()
    print_matrix()
    print()

    print("Перевірка сценаріїв")
    print("-" * 78)
    allowed = denied = 0
    for title, principal, permission, resource in SCENARIOS:
        try:
            guard.enforce(principal, permission, resource)
        except AccessDenied as exc:
            denied += 1
            print(f"  ВІДМОВА   {title:<45} {exc.decision.reason}")
        else:
            allowed += 1
            print(f"  дозволено {title}")

    print("-" * 78)
    print(f"Дозволено: {allowed}   Відмовлено: {denied}   Записів аудиту: {len(guard.audit)}")
    print()

    print("Журнал аудиту (останні 5 записів)")
    print("-" * 78)
    for rec in guard.audit[-5:]:
        verdict = "ALLOW" if rec.allowed else "DENY"
        print(f"  {verdict:<5} {rec.user_id:<4} {rec.role:<16} {rec.permission:<18} {rec.reason}")


if __name__ == "__main__":
    main()
