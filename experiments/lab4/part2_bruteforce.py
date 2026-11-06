#!/usr/bin/env python3
"""ЛР4, частина 2: порівняння стійкості SHA-256 та bcrypt до перебору.

Створює рядок «pass: <прізвище>», хешує його SHA-256 та bcrypt (cost=12),
формує словник із 20 кандидатів (правильний — останній) і запускає атаку
перебором для кожного хешу, фіксуючи час.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bcrypt

from lab4.common import SURNAME, parse_args

COST = 12
DICT_SIZE = 20


def make_dictionary(target: str) -> list[str]:
    """19 правдоподібних, але хибних кандидатів + правильний останнім."""
    base = f"pass: {SURNAME}"
    wrong = [f"pass: {SURNAME}{suffix}" for suffix in
             ["1", "12", "123", "2024", "2025", "2026", "!", "01", "02", "admin"]]
    wrong += [f"pass: {w}" for w in ["Tovtov", "Tovt R", "TovtR", "tovt", "TOVT",
                                     "Tovt1", "Tovt2", "Tovt_", "Tovt "]]
    wrong = [w for w in wrong if w != target][:DICT_SIZE - 1]
    return wrong + [target]


def run_bruteforce(algo: str, target_hash: str, dictionary: list[str]) -> tuple[float, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(dictionary))
        dict_path = fh.name
    script = Path(__file__).with_name("brute_force.py")
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(script), "--algo", algo, "--hash", target_hash, "--dict", dict_path],
        capture_output=True, text=True, check=True,
    )
    elapsed = time.perf_counter() - started
    print(proc.stdout.rstrip())
    print(f"--> wall time: {elapsed:.3f} s")
    print("-" * 60)
    return elapsed, proc.stdout


def main() -> None:
    args = parse_args()
    secret = f"pass: {SURNAME}"
    print(f"варіант:            {args.variant}")
    print(f"рядок:              {secret!r}")
    print()

    hash_sha = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    hash_bcrypt = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(COST)).decode()

    print(f"Хеш №5 (SHA-256):   {hash_sha}")
    print(f"Хеш №6 (bcrypt-12): {hash_bcrypt}")
    print()

    dictionary = make_dictionary(secret)
    print(f"Словник: {len(dictionary)} кандидатів, правильний — останній")
    print()

    print("=== Атака на SHA-256 ===")
    t_sha, _ = run_bruteforce("sha256", hash_sha, dictionary)
    print("=== Атака на bcrypt (cost=12) ===")
    t_bcrypt, _ = run_bruteforce("bcrypt", hash_bcrypt, dictionary)

    print()
    print(f"SHA-256: {t_sha:.3f} с")
    print(f"bcrypt:  {t_bcrypt:.3f} с")
    print(f"Різниця: у {t_bcrypt / t_sha:.0f} разів")
    print()
    print("Висновок: SHA-256 обчислюється за мікросекунди, тому перебір словника")
    print("не створює жодних перешкод. bcrypt із параметром вартості 12 навмисно")
    print("виконує тисячі повільних ітерацій, тому кожна перевірка коштує сотні")
    print("мілісекунд, а повний перебір реального словника стає економічно")
    print("недоцільним. Саме тому політика проєкту вимагає bcrypt для паролів.")


if __name__ == "__main__":
    main()
