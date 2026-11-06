"""Перевірка прав безпосередньо перед виконанням захищеної операції.

Принцип (SR-12): приховування елементів інтерфейсу не є контролем доступу.
Кожна захищена операція починається з виклику ``Guard.check`` або
декоратора ``@require``, який виконується в момент виклику, а не під час
побудови інтерфейсу.
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass, field
from typing import Callable

from .model import Decision, Permission, Policy, Principal


class AccessDenied(Exception):
    """Виникає, коли політика заборонила операцію."""

    def __init__(self, decision: Decision, permission: Permission):
        super().__init__(f"access denied: {permission.value} ({decision.reason})")
        self.decision = decision
        self.permission = permission


@dataclass
class AuditRecord:
    timestamp: float
    user_id: str
    role: str
    permission: str
    resource: dict
    allowed: bool
    reason: str


@dataclass
class Guard:
    policy: Policy = field(default_factory=Policy)
    audit: list[AuditRecord] = field(default_factory=list)

    def check(self, principal: Principal, permission: Permission,
              resource: dict | None = None) -> Decision:
        decision = self.policy.evaluate(principal, permission, resource)
        self.audit.append(AuditRecord(
            timestamp=time.time(),
            user_id=principal.user_id,
            role=principal.role.value,
            permission=permission.value,
            resource=dict(resource or {}),
            allowed=decision.allowed,
            reason=decision.reason,
        ))
        return decision

    def enforce(self, principal: Principal, permission: Permission,
                resource: dict | None = None) -> None:
        decision = self.check(principal, permission, resource)
        if not decision:
            raise AccessDenied(decision, permission)


def require(guard: Guard, permission: Permission,
            resource: Callable[..., dict] | None = None):
    """Декоратор: перевіряє право перед викликом функції.

    ``resource`` — функція, що будує словник ресурсу з аргументів виклику.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(principal: Principal, *args, **kwargs):
            res = resource(*args, **kwargs) if resource else {}
            guard.enforce(principal, permission, res)
            return func(principal, *args, **kwargs)

        return wrapper

    return decorator
