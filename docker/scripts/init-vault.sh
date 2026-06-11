#!/bin/bash
# Bootstrap Vault for the dev compose stack.
set -euo pipefail

export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-root-dev-only}

vault status

# KV v2
vault secrets enable -path=secret kv-v2 || true
# Transit engine
vault secrets enable transit || true
vault write -f transit/keys/session-encryption type=aes256-gcm96 || true
vault write -f transit/keys/field-encryption type=aes256-gcm96 || true
# PKI (root for dev only)
vault secrets enable pki || true
vault secrets tune -max-lease-ttl=87600h pki
vault write -field=certificate pki/root/generate/internal \
    common_name="SecureBank Dev CA" ttl=87600h > /tmp/ca.pem
vault write pki/roles/auth-service \
    allowed_domains=securebank.local allow_subdomains=true max_ttl=24h
vault write pki/roles/account-service \
    allowed_domains=securebank.local allow_subdomains=true max_ttl=24h
vault write pki/roles/transaction-service \
    allowed_domains=securebank.local allow_subdomains=true max_ttl=24h
# AppRole
vault auth enable approle || true
for svc in auth-service account-service transaction-service fraud-detection-service notification-service; do
  vault policy write $svc - <<EOF
path "transit/encrypt/session-encryption" { capabilities = ["update"] }
path "transit/decrypt/session-encryption" { capabilities = ["update"] }
path "transit/encrypt/field-encryption"   { capabilities = ["update"] }
path "transit/decrypt/field-encryption"   { capabilities = ["update"] }
path "secret/data/$svc/*"                 { capabilities = ["read"] }
path "pki/issue/$svc"                     { capabilities = ["update"] }
EOF
  vault write auth/approle/role/$svc token_policies=$svc token_ttl=1h token_max_ttl=24h
done

echo "Vault bootstrap complete."
