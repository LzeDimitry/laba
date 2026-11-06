"""Модель користувача та сховище облікових записів.

Ідентифікатор користувача (``user_id``) є незмінним внутрішнім ключем.
Адреса електронної пошти використовується як публічний ідентифікатор для
входу і може бути змінена без втрати зв'язків у системі.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .passwords import hash_password, verify_password


@dataclass
class User:
    user_id: str
    email: str
    password_hash: str
    role: str = "viewer"
    mfa_secret: str | None = None
    disabled: bool = False
    failed_attempts: int = 0
    locked: bool = False
    metadata: dict = field(default_factory=dict)

    def public(self) -> dict:
        """Подання без чутливих полів (для журналів та API)."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role,
            "disabled": self.disabled,
            "locked": self.locked,
        }


class UserStore:
    """Просте файлове сховище користувачів (JSON).

    У навчальному проєкті замінює базу даних; інтерфейс навмисно вузький,
    щоб у подальшому замінити реалізацію без зміни викличного коду.
    """

    def __init__(self, path: str | Path, cost: int = 12):
        self.path = Path(path)
        self.cost = cost
        self._users: dict[str, User] = {}
        if self.path.exists():
            self._load()

    # ---------- CRUD ----------
    def _load(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self._users = {u["user_id"]: User(**u) for u in data}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(u) for u in self._users.values()]
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def create(self, email: str, password: str, role: str = "viewer",
               mfa_secret: str | None = None) -> User:
        if self.find_by_email(email) is not None:
            raise ValueError(f"user with email {email!r} already exists")
        user = User(
            user_id=secrets.token_hex(8),
            email=email.strip().lower(),
            password_hash=hash_password(password, self.cost),
            role=role,
            mfa_secret=mfa_secret,
        )
        self._users[user.user_id] = user
        self._save()
        return user

    def all(self) -> Iterable[User]:
        return self._users.values()

    def get(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def find_by_email(self, email: str) -> User | None:
        email = email.strip().lower()
        for user in self._users.values():
            if user.email == email:
                return user
        return None

    # ---------- автентифікація ----------
    MAX_FAILED_ATTEMPTS = 5

    def authenticate(self, email: str, password: str) -> User | None:
        """Перевіряє облікові дані.

        Повертає користувача лише за умов: акаунт існує, не вимкнений, не
        заблокований і пароль збігається. Невдала спроба збільшує лічильник
        і після MAX_FAILED_ATTEMPTS блокує акаунт.
        """
        user = self.find_by_email(email)
        if user is None or user.disabled:
            return None
        if user.locked:
            return None
        if not verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.locked = True
            self._save()
            return None
        user.failed_attempts = 0
        self._save()
        return user
