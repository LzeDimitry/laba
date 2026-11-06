"""Керування станом автентифікованого користувача (сесії).

Властивості згідно з політикою безпеки (SR-11):
* токен сесії генерується криптографічно стійким генератором;
* у сховищі зберігається лише SHA-256 від токена, а не сам токен;
* діє ідлінг-таймаут і абсолютний час життя;
* токен ротується після підвищення привілеїв або повторної автентифікації;
* вихід із системи негайно робить токен недійсним.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field

IDLE_TIMEOUT = 15 * 60          # 15 хвилин бездіяльності
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 годин незалежно від активності


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Session:
    user_id: str
    created_at: float
    last_seen: float
    expires_at: float
    mfa_passed: bool = False
    meta: dict = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        now = now or time.time()
        return now >= self.expires_at or now - self.last_seen > IDLE_TIMEOUT


class SessionStore:
    """Сховище активних сесій у пам'яті процесу."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}  # sha256(token) -> Session

    def create(self, user_id: str, mfa_passed: bool = False, meta: dict | None = None) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        self._sessions[_digest(token)] = Session(
            user_id=user_id,
            created_at=now,
            last_seen=now,
            expires_at=now + ABSOLUTE_TIMEOUT,
            mfa_passed=mfa_passed,
            meta=meta or {},
        )
        return token

    def get(self, token: str, touch: bool = True) -> Session | None:
        key = _digest(token)
        session = self._sessions.get(key)
        if session is None:
            return None
        if session.is_expired():
            del self._sessions[key]
            return None
        if touch:
            session.last_seen = time.time()
        return session

    def verify_token(self, token: str, expected_token: str) -> bool:
        """Порівняння токенів у сталий час (захист від timing-атак)."""
        return secrets.compare_digest(_digest(token), _digest(expected_token))

    def rotate(self, token: str) -> str | None:
        """Видає новий токен замість наявного (наприклад, після зміни пароля)."""
        session = self.get(token)
        if session is None:
            return None
        self.revoke(token)
        new_token = self.create(session.user_id, session.mfa_passed, session.meta)
        return new_token

    def revoke(self, token: str) -> bool:
        return self._sessions.pop(_digest(token), None) is not None

    def revoke_all(self, user_id: str) -> int:
        keys = [k for k, s in self._sessions.items() if s.user_id == user_id]
        for k in keys:
            del self._sessions[k]
        return len(keys)

    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if not s.is_expired())
