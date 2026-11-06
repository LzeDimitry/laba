#!/usr/bin/env python3
"""ЛР7: цілісність (SHA-256), автентичність (HMAC) та AES-GCM.

Демонструє лавинний ефект, чутливість HMAC до зміни одного біта ключа та
виявлення підміни байта шифротексту автентифікованим шифруванням.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import lab_lib
from suc.crypto import aes_gcm_decrypt, aes_gcm_encrypt, generate_key, tamper
from suc.integrity import (
    flip_bit,
    generate_hmac_key,
    hamming_distance_bytes,
    hamming_distance_hex,
    hmac_sha256,
    sha256_hex,
    verify_hmac,
)

GROUP = "KBZI-24-2"
SURNAME = "Tovt"
NAME = "Rastislav"


def main() -> None:
    variant = lab_lib.parse_args("ЛР7").variant
    message = f"{lab_lib.year()}_{GROUP}_{SURNAME}_{NAME}_варіант:{variant:02d}"
    data = message.encode("utf-8")

    print(f"Повідомлення:        {message}")
    print()

    h1 = sha256_hex(data)
    modified = message.replace(str(variant).zfill(2), "99", 1).encode("utf-8")
    h2 = sha256_hex(modified)
    print(f"Хеш №1 (SHA-256):    {h1}")
    print(f"Хеш №2 (змінено 2 символи): {h2}")
    print(f"  різних бітів:      {hamming_distance_hex(h1, h2)} із 256")
    print()

    key = generate_hmac_key()
    mac1 = hmac_sha256(key, data)
    print(f"Ключ №1 (hex):       {key.hex()}")
    print(f"HMAC №1:             {mac1}")
    print(f"  перевірка оригіналу:            {verify_hmac(key, data, mac1)}")
    print(f"  перевірка зміненого повідомлення: {verify_hmac(key, modified, mac1)}")
    print()

    key2 = flip_bit(key, 0)
    print(f"Ключ №2 (змінено 1 біт): {key2.hex()}")
    print(f"  бітів різниці в ключі:  {hamming_distance_bytes(key, key2)}")
    print(f"  перевірка HMAC №1 ключем №2: {verify_hmac(key2, data, mac1)}")
    mac2 = hmac_sha256(key2, data)
    print(f"HMAC №2:             {mac2}")
    print(f"  різних бітів між HMAC №1 та №2: {hamming_distance_hex(mac1, mac2)} із 256")
    print()

    aes_key = generate_key()
    sealed = aes_gcm_encrypt(aes_key, data, aad=b"release-manifest")
    print(f"AES-GCM ключ:        {aes_key.hex()}")
    print(f"Nonce:               {sealed.nonce.hex()}")
    print(f"Шифротекст+тег:      {sealed.ciphertext.hex()}")
    print(f"  розшифрування:     {aes_gcm_decrypt(aes_key, sealed.nonce, sealed.ciphertext, aad=b'release-manifest').decode()}")
    broken = tamper(sealed.ciphertext)
    try:
        aes_gcm_decrypt(aes_key, sealed.nonce, broken, aad=b"release-manifest")
        print("  підміна байта:     НЕ ВИЯВЛЕНО")
    except Exception as exc:  # InvalidTag
        print(f"  підміна байта:     виявлено ({type(exc).__name__})")
    print()
    print("Висновок: SHA-256 виявляє будь-яку модифікацію, але не захищає від")
    print("підміни разом з еталоном. HMAC додає секретний ключ і реагує навіть на")
    print("зміну одного біта. AES-GCM виявляє підміну байта шифротексту без")
    print("окремого еталона, тому саме він використовується для даних проєкту.")


if __name__ == "__main__":
    main()
