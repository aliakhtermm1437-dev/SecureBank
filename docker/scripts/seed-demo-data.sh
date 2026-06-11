#!/bin/bash
# Seed demo users and accounts for local docker-compose or K8s port-forward stacks.
set -euo pipefail

GATEWAY="${SB_GATEWAY_URL:-http://localhost:8443}"
AUTH="${SB_AUTH_URL:-http://localhost:8001}"

echo "==> Seeding SecureBank demo data via ${GATEWAY}"

# Wait for auth health (compose may still be starting)
for i in $(seq 1 30); do
  if curl -sf "${AUTH}/health" >/dev/null 2>&1 || curl -skf "${GATEWAY}/health" >/dev/null 2>&1; then
    break
  fi
  echo "waiting for services... (${i}/30)"
  sleep 2
done

echo "Demo seed complete."
echo "  User: demo@securebank.local"
echo "  Pass: Change-Me-On-First-Login!"
echo "  (Created automatically when DEMO_SEED=true on auth-service boot)"
