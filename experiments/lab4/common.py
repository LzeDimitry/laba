"""Спільні параметри для лабораторної роботи №4.

Базовий рядок формується за шаблоном з методички:
    «[поточний_рік]_[група]_[прізвище_студента]_[номер_варіанту]_»
"""

from __future__ import annotations

import argparse
import datetime as dt

GROUP = "KBZI-24-2"
SURNAME = "Tovt"
DEFAULT_VARIANT = 1
PAD_BYTE = "_"
TARGET_BYTES = 72


def base_string(variant: int) -> str:
    year = dt.date.today().year
    return f"{year}_{GROUP}_{SURNAME}_{variant:02d}_"


def padded_base(variant: int) -> str:
    """Доповнює базовий рядок символами «_» до 72 байт UTF-8."""
    text = base_string(variant)
    padding = TARGET_BYTES - len(text.encode("utf-8"))
    if padding < 0:
        raise ValueError("base string longer than 72 bytes")
    return text + PAD_BYTE * padding


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Лабораторна робота №4 з БПЗ")
    parser.add_argument("--variant", type=int, default=DEFAULT_VARIANT)
    return parser.parse_args(argv)
