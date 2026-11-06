"""Хешування та перевірка паролів.

Політика проєкту (SR-10) вимагає bcrypt з параметром вартості не нижче 12.
Модуль також явно працює з обмеженням bcrypt у 72 байти, оскільки саме на
ньому побудована лабораторна робота №4.
"""

from __future__ import annotations

import bcrypt

#: Максимальна довжина входу, яку bcrypt бере до уваги (у байтах).
BCRYPT_MAX_BYTES = 72

#: Мінімальний параметр вартості згідно з політикою безпеки проєкту.
MIN_COST = 12


def prepare_password(password: str) -> bytes:
    """Перетворює пароль у байти UTF-8.

    Сучасний bcrypt (>= 4.1) відмовляється працювати з входами довшими за
    72 байти. Історично реалізації просто обрізали вхід на 72 байтах, тому
    функція явно фіксує цю поведінку: обрізає та документує факт обрізання.
    """
    raw = password.encode("utf-8")
    return raw[:BCRYPT_MAX_BYTES]


def hash_password(password: str, cost: int = MIN_COST) -> str:
    """Повертає bcrypt-хеш пароля у вигляді рядка."""
    if cost < MIN_COST:
        raise ValueError(f"cost must be >= {MIN_COST}, got {cost}")
    return bcrypt.hashpw(prepare_password(password), bcrypt.gensalt(cost)).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Перевіряє пароль відносно bcrypt-хешу."""
    try:
        return bcrypt.checkpw(prepare_password(password), hashed.encode())
    except (ValueError, TypeError):
        return False


def bytes_length(text: str) -> int:
    """Довжина рядка у байтах UTF-8 (не в символах)."""
    return len(text.encode("utf-8"))
