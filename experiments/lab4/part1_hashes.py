#!/usr/bin/env python3
"""ЛР4, частина 1: чотири bcrypt-хеші та їх попарна перевірка.

Ключова особливість bcrypt — обмеження входу 72 байтами. Базовий рядок
доповнюється саме до 72 байт, тому всі доповнення після 72-го байта
відкидаються, і хеші №1–№3 виявляються однаковими.
"""

from __future__ import annotations

import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bcrypt

from lab4.common import base_string, padded_base, parse_args

COST = 12
ALPHABET = string.ascii_letters + string.digits


def bcrypt_hash(text: str) -> str:
    """Хешує вхід, обрізаючи його до 72 байт (історична поведінка bcrypt)."""
    raw = text.encode("utf-8")[:72]
    return bcrypt.hashpw(raw, bcrypt.gensalt(COST)).decode()


def bcrypt_check(text: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(text.encode("utf-8")[:72], hashed.encode())
    except ValueError:
        return False


def main() -> None:
    args = parse_args()
    v = args.variant

    base = base_string(v)
    padded = padded_base(v)
    extra_ten = "".join(secrets.choice(ALPHABET) for _ in range(10))

    cases = {
        1: padded,                      # базовий рядок, доповнений до 72 байт
        2: padded + "1",                # + символ «1»
        3: padded + extra_ten,          # + 10 псевдовипадкових символів
        4: padded[:-1],                 # без останнього «_»
    }

    print(f"варіант:            {v}")
    print(f"базовий рядок:      {base!r}")
    print(f"довжина (символи):  {len(base)}")
    print(f"довжина (байти):    {len(base.encode('utf-8'))}")
    print(f"після доповнення:   {len(padded.encode('utf-8'))} байт")
    print()

    hashes = {}
    for i, text in cases.items():
        hashes[i] = bcrypt_hash(text)
        print(f"Хеш №{i}: {hashes[i]}")

    print()
    print("Попарна перевірка (рядок -> хеш):")
    header = "        " + "".join(f"  Хеш №{j}" for j in cases)
    print(header)
    for i, text in cases.items():
        row = f"Рядок №{i}"
        for j, hashed in hashes.items():
            row += "  " + ("  так  " if bcrypt_check(text, hashed) else "  ні   ")
        print(row)

    print()
    trivially_equal = bcrypt_check(cases[2], hashes[1]) and bcrypt_check(cases[3], hashes[1])
    print("Усі три перші хеші різні як рядки, оскільки bcrypt щоразу генерує нову")
    print("випадкову сіль. Проте кожен із них успішно перевіряється проти всіх")
    print("трьох рядків №1–№3: входи еквівалентні, бо відрізняються лише після")
    print("72-го байта, який bcrypt не враховує.")
    print(f"  рядок №2 проходить перевірку проти хешу №1: {bcrypt_check(cases[2], hashes[1])}")
    print(f"  рядок №3 проходить перевірку проти хешу №1: {bcrypt_check(cases[3], hashes[1])}")
    print(f"  рядок №4 проходить перевірку проти хешу №1: {bcrypt_check(cases[4], hashes[1])}")
    print()
    print("Рядок №4 коротший за 72 байти, тому відрізняється в межах значущої")
    print("частини входу і не проходить жодної перевірки, крім власного хешу.")
    print()
    print("Висновок: bcrypt враховує лише перші 72 байти входу. Доповнення рядка")
    print("понад цю межу не додає стійкості, а зміна довжини в межах 72 байт")
    print("змінює результат повністю. Сіль унеможливлює порівняння хешів як")
    print("рядків, тому перевірка виконується лише функцією checkpw.")


if __name__ == "__main__":
    main()
