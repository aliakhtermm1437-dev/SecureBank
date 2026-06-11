#!/bin/bash
# Quick mTLS cert generation for the dev compose stack. NOT for production.
set -euo pipefail

OUT=${1:-./certs}
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -subj "/CN=SecureBank Dev CA/O=SecureBank" \
  -keyout ca.key -out ca.crt

for svc in auth-service account-service transaction-service \
           fraud-detection-service notification-service api-gateway; do
  openssl req -newkey rsa:3072 -nodes -subj "/CN=$svc.securebank.local/O=SecureBank" \
    -keyout "$svc.key" -out "$svc.csr"
  openssl x509 -req -in "$svc.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 90 -out "$svc.crt" -extfile <(printf "subjectAltName=DNS:%s,DNS:%s.securebank.local" "$svc" "$svc")
  rm "$svc.csr"
done

echo "Certs written to $OUT"
