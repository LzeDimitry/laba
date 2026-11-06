#!/usr/bin/env python3
"""ЛР6: шифрування AES-CTR та атака «відомий відкритий текст».

У режимі CTR шифротекст утворюється як XOR відкритого тексту з гамою
(результатом шифрування лічильника). Якщо зловмиснику відома хоча б одна
пара «відкритий текст — шифротекст», він відновлює гаму і може зашифрувати
нею будь-який власний текст, не знаючи ключа.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import lab_lib
from suc.crypto import aes_ctr_decrypt, aes_ctr_encrypt, generate_iv, generate_key

GROUP = "KBZI-24-2"
SURNAME = "Tovt"
NAME = "Rastislav"


def main() -> None:
    variant = lab_lib.parse_args("ЛР6").variant
    base = f"{lab_lib.year()}_{GROUP}_{SURNAME}_{NAME}_варіант:{variant:02d}"
    fake = base[:-2] + "99"  # альтернативний текст зловмисника

    key = generate_key()
    iv = generate_iv()

    print(f"Базовий рядок:       {base}")
    print(f"Довжина (байти):     {len(base.encode('utf-8'))}")
    print()
    print(f"Ключ №1 (hex):       {key.hex()}")
    print(f"Вектор №1 (hex):     {iv.hex()}")
    print()

    c1 = aes_ctr_encrypt(key, iv, base.encode("utf-8"))
    print(f"Шифротекст №1:       {c1.hex()}")
    print()

    # --- атака: відомий відкритий текст і відповідний шифротекст ---
    plain = base.encode("utf-8")
    gamma = bytes(a ^ b for a, b in zip(c1, plain))
    print("Атака (ключ вважається невідомим):")
    print(f"  Гама №1 (hex):     {gamma.hex()}")

    c2 = bytes(a ^ b for a, b in zip(gamma, fake.encode("utf-8")))
    print(f"  Шифротекст №2:     {c2.hex()}")
    print()

    recovered = aes_ctr_decrypt(key, iv, c2).decode("utf-8")
    print("Перевірка: шифротекст №2 розшифровано Ключем №1 та Вектором №1")
    print(f"  Отримано:          {recovered}")
    print(f"  Збігається з підміною: {recovered == fake}")
    print()
    print("Висновок: режим CTR не забезпечує автентичності. Знаючи одну пару")
    print("«відкритий текст — шифротекст», зловмисник відновлює гаму і формує")
    print("валідний шифротекст для довільного тексту без знання ключа. Для")
    print("захисту даних проєкту обрано AES-GCM, який додає тег автентифікації.")


if __name__ == "__main__":
    main()
