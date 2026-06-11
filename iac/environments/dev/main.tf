terraform {
  required_version = ">= 1.7.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes" }
    helm       = { source = "hashicorp/helm" }
    vault      = { source = "hashicorp/vault" }
  }
}

provider "kubernetes" {
  config_path    = "~/.kube/config"
  config_context = "kind-securebank-dev"
}

provider "helm" {
  kubernetes {
    config_path    = "~/.kube/config"
    config_context = "kind-securebank-dev"
  }
}

provider "vault" {
  address = "http://127.0.0.1:8200"
  token   = "root-dev-only"
}

module "namespaces" { source = "../../modules/kubernetes" }
module "vault"      { source = "../../modules/vault" }
module "monitoring" { source = "../../modules/monitoring" depends_on = [module.namespaces] }
