#!/usr/bin/env bash
# ЛР8: цифровий підпис ліцензії (RSA-PSS + SHA-256) засобами OpenSSL 3.
set -e
cd "$(dirname "$0")"
rm -rf work && mkdir -p work && cd work

echo "== 1. Формування файлу ліцензії =="
cat > license.json <<'JSON'
{
  "product_id": "secure-update-client",
  "license_owner": "Tovt Rastislav",
  "expires_at": "2027-06-30",
  "features": ["release.publish", "release.sign", "channel.beta"],
  "license_id": "SUC-2026-0001-7f3a"
}
JSON
cat license.json

echo
echo "== 2. Генерація пари ключів RSA 3072 =="
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem 2>/dev/null
openssl pkey -in private.pem -pubout -out public.pem
ls -l private.pem public.pem | awk '{print $1, $5, $9}'

echo
echo "== 3. Підпис ліцензії (RSA-PSS, SHA-256) =="
openssl dgst -sha256 -sign private.pem \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -out license.sig license.json
echo "license.sig: $(wc -c < license.sig) байт"

echo
echo "== 4. Перевірка підпису відкритим ключем =="
openssl dgst -sha256 -verify public.pem -signature license.sig \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto license.json

echo
echo "== 5. Підміна строку дії без оновлення підпису =="
sed -i 's/2027-06-30/2030-12-31/' license.json
grep expires_at license.json
openssl dgst -sha256 -verify public.pem -signature license.sig \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto license.json || true
