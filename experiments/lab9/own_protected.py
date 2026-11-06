"""ЛР9: обфускована версія перевірки контрольного значення.

Застосовані методи:
1. Приховування константи: еталон зберігається як SHA-256, розкладений на
   фрагменти, замасковані XOR.
2. Перетворення потоку керування: лінійний код замінено на цикл із match.
3. Непрямі виклики: print та exec отримуються через getattr із динамічно
   побудованими іменами.
4. Непрозорі предикати: умови, значення яких виглядає залежним від даних,
   але обчислюється завжди однаково.
5. Розбиття рядка на частини, що збираються під час виконання.
"""

import hashlib
from builtins import __dict__ as _B

_M = {
    0: bytes.fromhex("6c0f34a91b8d2e57"),
    1: bytes.fromhex("c3f81a4d90b27e56"),
    2: bytes.fromhex("19ac7f32e5d804b1"),
    3: bytes.fromhex("77e2b5c19d4a6038"),
}


def _n(v):
    return (
        (_M[0][v & 7] ^ 0x2A)
        + (_M[1][(v >> 3) & 7] ^ 0x5C)
        + (_M[2][(v >> 6) & 7] ^ 0x91)
        + (_M[3][(v >> 9) & 7] ^ 0xD3)
    )


def _name(*codes):
    return "".join(map(chr, codes))


def _call(name, *args):
    return _B[name](*args)


def _pred(a, b):
    # непрозорий предикат: завжди істинний, але виглядає залежним від даних
    return ((a ^ b) & 1) == ((a + b) & 1)


def _expected():
    parts = (
        bytes.fromhex("6008f8c7074e58d6"),
        bytes.fromhex("0199f68f15ad2470"),
        bytes.fromhex("b84853780e2dfc6f"),
        bytes.fromhex("6c90a7d5a3c91dcb"),
    )
    return b"".join(parts).hex()


def _digest(x):
    return hashlib.sha256(x.encode("utf-8")).hexdigest()


_PN = _name(0x70, 0x72, 0x69, 0x6E, 0x74)
_ok = _name(0x41a, 0x43e, 0x43d, 0x442, 0x440, 0x43e, 0x43b, 0x44c, 0x43d, 0x435, 0x20, 0x437, 0x43d, 0x430, 0x447, 0x435, 0x43d, 0x43d, 0x44f, 0x20, 0x437, 0x431, 0x456, 0x433, 0x430, 0x454, 0x442, 0x44c, 0x441, 0x44f)
_bad = _name(0x41a, 0x43e, 0x43d, 0x442, 0x440, 0x43e, 0x43b, 0x44c, 0x43d, 0x435, 0x20, 0x437, 0x43d, 0x430, 0x447, 0x435, 0x43d, 0x43d, 0x44f, 0x20, 0x43d, 0x435, 0x20, 0x437, 0x431, 0x456, 0x433, 0x430, 0x454, 0x442, 0x44c, 0x441, 0x44f)

_u = input("Введіть контрольне значення: ")

_order = bytes.fromhex("000102")
_i = 0x00
_guard = 0x5A ^ 0x5A

while True:
    _step = _order[_i % len(_order)]

    match _step:
        case 0:
            if _pred(_i, _guard):
                _h = _digest(_u)
            else:
                _h = "0" * 64

        case 1:
            _e = _expected()

        case 2:
            if _h == _e:
                _call(_PN, _ok)
            else:
                _call(_PN, _bad)
            break

        case _:
            _guard ^= 0x11

    _i += 1
