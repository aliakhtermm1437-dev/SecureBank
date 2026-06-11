terraform {
  required_version = ">= 1.7.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes" }
    helm       = { source = "hashicorp/helm" }
    vault      = { source = "hashicorp/vault" }
    kafka      = { source = "Mongey/kafka" }
  }
  backend "s3" {
    bucket         = "securebank-tfstate-prod"
    key            = "prod/securebank.tfstate"
    region         = "ap-southeast-1"
    encrypt        = true
    dynamodb_table = "securebank-tflock"
  }
}

provider "kubernetes" { config_path = "~/.kube/config-prod" }
provider "helm"       { kubernetes { config_path = "~/.kube/config-prod" } }
provider "vault" {
  address   = var.vault_addr
  namespace = "securebank"
  # Token via VAULT_TOKEN env-var or AppRole.
}
provider "kafka" {
  bootstrap_servers = [var.kafka_bootstrap]
  tls_enabled       = true
  sasl_mechanism    = "scram-sha512"
  sasl_username     = var.kafka_admin_user
  sasl_password     = var.kafka_admin_pass
}

variable "vault_addr"        { type = string }
variable "kafka_bootstrap"   { type = string }
variable "kafka_admin_user"  { type = string sensitive = true }
variable "kafka_admin_pass"  { type = string sensitive = true }

module "namespaces" { source = "../../modules/kubernetes" }
module "vault"      { source = "../../modules/vault" }
module "kafka"      { source = "../../modules/kafka" }
module "monitoring" { source = "../../modules/monitoring" depends_on = [module.namespaces] }
