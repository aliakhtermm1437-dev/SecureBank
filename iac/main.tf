# Root module — wires the per-env stacks together. This file is intentionally
# small; concrete env config lives in environments/{dev,prod}.

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.32" }
    helm       = { source = "hashicorp/helm",       version = "~> 2.14" }
    vault      = { source = "hashicorp/vault",      version = "~> 4.4" }
    kafka      = { source = "Mongey/kafka",         version = "~> 0.7" }
  }

  backend "s3" {
    bucket         = "securebank-tfstate"
    key            = "global/securebank.tfstate"
    region         = "ap-southeast-1"
    encrypt        = true
    dynamodb_table = "securebank-tflock"
  }
}
