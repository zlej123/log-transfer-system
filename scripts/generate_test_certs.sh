#!/usr/bin/env bash
# Generate a private test CA plus server/client certificates for local runs.
# Production deployments must use organization-managed PKI material.
set -euo pipefail
OUT=${1:-certs}
mkdir -p "$OUT"
chmod 700 "$OUT"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/ca.key" >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$OUT/ca.key" -days 3650 \
  -subj "/CN=LGX Development CA" -out "$OUT/ca.crt"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/server.key" >/dev/null 2>&1
openssl req -new -key "$OUT/server.key" -subj "/CN=localhost" -out "$OUT/server.csr"
cat > "$OUT/server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -sha256 -in "$OUT/server.csr" -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" -CAcreateserial -days 825 -extfile "$OUT/server.ext" \
  -out "$OUT/server.crt" >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/client.key" >/dev/null 2>&1
openssl req -new -key "$OUT/client.key" -subj "/CN=lgx-client" -out "$OUT/client.csr"
cat > "$OUT/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 -in "$OUT/client.csr" -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" -CAcreateserial -days 825 -extfile "$OUT/client.ext" \
  -out "$OUT/client.crt" >/dev/null 2>&1

rm -f "$OUT"/*.csr "$OUT"/*.ext "$OUT"/*.srl
chmod 600 "$OUT"/*.key
chmod 644 "$OUT"/*.crt
printf 'generated mTLS test material in %s\n' "$OUT"
