"""Тести обфускованої програми (ЛР9).

Перевіряється головна властивість обфускації: функціональна логіка не
змінилася, а контрольний рядок відсутній у коді у відкритому вигляді.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1] / "experiments" / "lab9"
CONTROL = "2026_KBZI-24-2_Tovt_Rastislav_варіант:01"


def run(script: str, value: str) -> str:
    proc = subprocess.run(
        [sys.executable, str(LAB / script)],
        input=value + "\n", capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.parametrize("value", [CONTROL, CONTROL + "x", "", "wrong"])
def test_protected_matches_plain(value):
    plain = run("own_plain.py", value)
    protected = run("own_protected.py", value)
    assert plain.split()[-1] == protected.split()[-1]


def test_control_value_not_present_in_protected_source():
    source = (LAB / "own_protected.py").read_text(encoding="utf-8")
    assert CONTROL not in source
    assert "Tovt" not in source


def test_control_value_present_in_plain_source():
    source = (LAB / "own_plain.py").read_text(encoding="utf-8")
    assert CONTROL in source


@pytest.mark.parametrize("script", ["appendix_original.py", "appendix_obf1.py", "appendix_obf2.py"])
def test_appendix_variants_behave_identically(script):
    assert "дозволено" in run(script, "Secret123")
    assert "заборонено" in run(script, "nope")
