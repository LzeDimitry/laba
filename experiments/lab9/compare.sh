#!/usr/bin/env bash
# ЛР9: перевірка однакової поведінки всіх варіантів
cd "$(dirname "$0")"
for f in appendix_original appendix_obf1 appendix_obf2; do
  ok=$(printf 'Secret123\n' | python3 "$f.py" | tail -1 | sed 's/^Введіть [^:]*: //')
  no=$(printf 'wrong\n' | python3 "$f.py" | tail -1 | sed 's/^Введіть [^:]*: //')
  printf '%-20s | %-22s | %s\n' "$f" "$ok" "$no"
done

echo
for f in own_plain own_protected; do
  ok=$(printf '2026_KBZI-24-2_Tovt_Rastislav_варіант:01\n' | python3 "$f.py" | tail -1 | sed 's/^Введіть [^:]*: //')
  no=$(printf 'wrong\n' | python3 "$f.py" | tail -1 | sed 's/^Введіть [^:]*: //')
  printf '%-20s | %-38s | %s\n' "$f" "$ok" "$no"
done
