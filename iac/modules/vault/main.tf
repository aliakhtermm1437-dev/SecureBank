terraform {
  required_providers { vault = { source = "hashicorp/vault" } }
}

resource "vault_mount" "kv" {
  path = "secret"
  type = "kv-v2"
}

resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "session_enc" {
  backend = vault_mount.transit.path
  name    = "session-encryption"
  type    = "aes256-gcm96"
  exportable = false
  deletion_allowed = false
}

resource "vault_transit_secret_backend_key" "field_enc" {
  backend = vault_mount.transit.path
  name    = "field-encryption"
  type    = "aes256-gcm96"
  exportable = false
  deletion_allowed = false
}

resource "vault_mount" "pki" {
  path                      = "pki"
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400 * 365 * 10
}

resource "vault_auth_backend" "approle" {
  type = "approle"
}

# Per-service AppRole + policy.
locals { services = ["auth-service", "account-service", "transaction-service", "fraud-detection-service", "notification-service"] }

resource "vault_policy" "svc" {
  for_each = toset(local.services)
  name     = each.value
  policy = <<-EOT
    path "transit/encrypt/session-encryption" { capabilities = ["update"] }
    path "transit/decrypt/session-encryption" { capabilities = ["update"] }
    path "transit/encrypt/field-encryption"   { capabilities = ["update"] }
    path "transit/decrypt/field-encryption"   { capabilities = ["update"] }
    path "secret/data/${each.value}/*"        { capabilities = ["read"] }
    path "pki/issue/${each.value}"            { capabilities = ["update"] }
  EOT
}

resource "vault_approle_auth_backend_role" "svc" {
  for_each       = toset(local.services)
  backend        = vault_auth_backend.approle.path
  role_name      = each.value
  token_policies = [each.value]
  token_ttl      = 3600
  token_max_ttl  = 86400
}
