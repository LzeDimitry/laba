#!/usr/bin/env python3
"""ЛР4: скрипт атаки перебором за словником.

Отримує на вхід хеш і тип алгоритму, послідовно перевіряє кандидатів зі
словника, припиняє роботу після знаходження збігу та вимірює фактичний час
виконання.

Приклад:
    python brute_force.py --algo sha256 \\
        --hash 5f4dcc3b5aa765d61d8327deb882cf99... --dict dict.txt
"""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

import bcrypt


def check(candidate: str, target: str, algo: str) -> bool:
    if algo == "sha256":
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest() == target
    if algo == "bcrypt":
        try:
            return bcrypt.checkpw(candidate.encode("utf-8")[:72], target.encode())
        except ValueError:
            return False
    raise ValueError(f"unsupported algorithm: {algo}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", required=True)
    parser.add_argument("--algo", choices=["sha256", "bcrypt"], required=True)
    parser.add_argument("--dict", required=True, help="файл зі словником (один кандидат на рядок)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    candidates = [line.rstrip("\n") for line in Path(args.dict).read_text(encoding="utf-8").splitlines() if line]
    if not candidates:
        raise SystemExit("empty dictionary")

    print(f"алгоритм:   {args.algo}")
    print(f"хеш:        {args.hash[:40]}{'...' if len(args.hash) > 40 else ''}")
    print(f"словник:    {len(candidates)} кандидатів")
    print()

    started = time.perf_counter()
    found = None
    for index, candidate in enumerate(candidates, 1):
        attempt_started = time.perf_counter()
        ok = check(candidate, args.hash, args.algo)
        elapsed_ms = (time.perf_counter() - attempt_started) * 1000
        status = "ЗБІГ" if ok else "ні"
        if not args.quiet:
            print(f"  {index:2d}. {candidate!r:<22} {status:<5} {elapsed_ms:8.2f} мс")
        if ok:
            found = candidate
            break
    total = time.perf_counter() - started

    print()
    if found is None:
        print(f"Пароль не знайдено. Час: {total:.3f} с")
        raise SystemExit(1)
    print(f"Знайдено: {found!r}")
    print(f"Перевірено кандидатів: {index} з {len(candidates)}")
    print(f"Загальний час: {total:.3f} с")
    print(f"Середній час на кандидата: {total / index * 1000:.2f} мс")


if __name__ == "__main__":
    main()
