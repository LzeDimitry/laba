"""Спільні утиліти для лабораторних експериментів."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT.parent / "src"


def add_src_path() -> None:
    sys.path.insert(0, str(SRC))


def year() -> int:
    return dt.date.today().year


def parse_args(description: str = "лабораторна робота"):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--variant", type=int, default=1)
    return parser.parse_args()
