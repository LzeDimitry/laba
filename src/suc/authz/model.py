"""Модель керування доступом (ЛР5).

Обрано **RBAC з елементами ABAC**:

* RBAC визначає, які дії доступні ролі в принципі;
* ABAC-умови уточнюють рішення залежно від атрибутів ресурсу (канал релізу)
  та контексту (наявність другого фактора, розділення обов'язків).

Такий вибір обґрунтований тим, що більшість операцій утиліти оновлень
природно групуються за ролями (адміністратор, менеджер релізів, аудитор), але
публікація у стабільний канал потребує додаткової умови — розділення
обов'язків між тим, хто готує реліз, і тим, хто його випускає.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Permission(str, Enum):
    RELEASE_READ = "release.read"
    RELEASE_PUBLISH = "release.publish"
    RELEASE_SIGN = "release.sign"
    CHANNEL_MANAGE = "channel.manage"
    USER_MANAGE = "user.manage"
    AUDIT_READ = "audit.read"
    LICENSE_MANAGE = "license.manage"


class Role(str, Enum):
    ADMIN = "admin"
    RELEASE_MANAGER = "release_manager"
    AUDITOR = "auditor"
    VIEWER = "viewer"


#: Базові дозволи ролі. Ключ — роль, значення — набір дозволів.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.RELEASE_MANAGER: frozenset({
        Permission.RELEASE_READ,
        Permission.RELEASE_PUBLISH,
        Permission.RELEASE_SIGN,
        Permission.LICENSE_MANAGE,
    }),
    Role.AUDITOR: frozenset({
        Permission.RELEASE_READ,
        Permission.AUDIT_READ,
    }),
    Role.VIEWER: frozenset({
        Permission.RELEASE_READ,
    }),
}

STABLE_CHANNEL = "stable"
BETA_CHANNEL = "beta"


@dataclass(frozen=True)
class Principal:
    """Суб'єкт, від імені якого виконується операція."""

    user_id: str
    role: Role
    mfa_passed: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # дозволяє `if decision:`
        return self.allowed


@dataclass
class Policy:
    """Політика доступу: RBAC + ABAC-умови."""

    role_permissions: dict[Role, frozenset[Permission]] = field(
        default_factory=lambda: dict(ROLE_PERMISSIONS))

    def evaluate(self, principal: Principal, permission: Permission,
                 resource: dict | None = None) -> Decision:
        resource = resource or {}

        granted = self.role_permissions.get(principal.role, frozenset())
        if permission not in granted:
            return Decision(False, f"роль {principal.role.value} не має дозволу {permission.value}")

        # ABAC-умова 1: підпис і публікація вимагають пройденого другого фактора
        if permission in (Permission.RELEASE_SIGN, Permission.RELEASE_PUBLISH) and not principal.mfa_passed:
            return Decision(False, "не пройдено другий фактор автентифікації")

        # ABAC-умова 2: розділення обов'язків для стабільного каналу
        channel = resource.get("channel")
        if permission is Permission.RELEASE_PUBLISH and channel == STABLE_CHANNEL:
            if principal.role is not Role.ADMIN:
                return Decision(False, "публікація у stable потребує ролі admin")
            if not resource.get("approved", False):
                return Decision(False, "відсутнє схвалення рев'ю для stable")

        # ABAC-умова 3: не можна керувати користувачами з роллю admin
        if permission is Permission.USER_MANAGE and resource.get("target_role") == Role.ADMIN:
            return Decision(False, "керування адміністраторами заборонено цим шляхом")

        # ABAC-умова 4: аудитор не може читати журнал іншого тенанта
        if permission is Permission.AUDIT_READ and resource.get("tenant") not in (None, resource.get("actor_tenant")):
            return Decision(False, "журнал належить іншому тенанту")

        return Decision(True, "дозволено")
