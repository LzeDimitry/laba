#!/usr/bin/env python3
"""ЛР9: порівняння статичної складності прозорої та обфускованої програм."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FILES = [
    "appendix_original.py",
    "appendix_obf1.py",
    "appendix_obf2.py",
    "own_plain.py",
    "own_protected.py",
]

BRANCHES = (ast.If, ast.While, ast.For, ast.Match, ast.Try)


def depth(node: ast.AST, current: int = 0) -> int:
    best = current
    for child in ast.iter_child_nodes(node):
        best = max(best, depth(child, current + 1))
    return best


def metrics(path: Path) -> dict:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = list(ast.walk(tree))
    funcs = [n for n in nodes if isinstance(n, ast.FunctionDef)]
    constants = [n for n in nodes if isinstance(n, ast.Constant)]
    strings = [c for c in constants if isinstance(c.value, str)]
    numeric = [c for c in constants if isinstance(c.value, int)]
    branches = [n for n in nodes if isinstance(n, BRANCHES)]
    calls = [n for n in nodes if isinstance(n, ast.Call)]
    return {
        "nodes": len(nodes),
        "funcs": len(funcs),
        "branches": len(branches),
        "calls": len(calls),
        "strings": len(strings),
        "numeric": len(numeric),
        "depth": depth(tree),
        "lines": len(path.read_text(encoding="utf-8").splitlines()),
    }


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    rows = []
    for name in FILES:
        path = base_dir / name
        if not path.exists():
            print(f"немає файлу: {name}")
            continue
        rows.append((name, metrics(path)))

    header = f"{'файл':<24}{'рядки':>7}{'вузли':>7}{'функц':>7}{'розг':>6}{'виклики':>9}{'рядки-конст':>13}{'числа':>7}{'глиб':>6}"
    print(header)
    print("-" * len(header))
    for name, m in rows:
        print(f"{name:<24}{m['lines']:>7}{m['nodes']:>7}{m['funcs']:>7}{m['branches']:>6}"
              f"{m['calls']:>9}{m['strings']:>13}{m['numeric']:>7}{m['depth']:>6}")

    by_name = dict(rows)
    if "own_plain.py" in by_name and "own_protected.py" in by_name:
        a, b = by_name["own_plain.py"], by_name["own_protected.py"]
        print()
        print("Приріст складності (own_protected відносно own_plain):")
        for key, label in [("lines", "рядків"), ("nodes", "вузлів AST"), ("funcs", "функцій"),
                           ("branches", "розгалужень"), ("calls", "викликів"),
                           ("strings", "рядкових констант"), ("numeric", "числових констант")]:
            ratio = b[key] / a[key] if a[key] else float("inf")
            print(f"  {label:<22} {a[key]:>4} -> {b[key]:<4} (x{ratio:.1f})")
        print()
        control = "2026_KBZI-24-2_Tovt_Rastislav"
        print("Наявність контрольного рядка у відкритому вигляді:")
        for name in ("own_plain.py", "own_protected.py"):
            present = control in (base_dir / name).read_text(encoding="utf-8")
            print(f"  {name:<18} {'є' if present else 'немає'}")


if __name__ == "__main__":
    main()
