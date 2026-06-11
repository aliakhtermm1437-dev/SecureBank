terraform {
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes" }
  }
}

variable "namespaces" {
  type    = list(string)
  default = ["securebank-edge", "securebank-app", "securebank-data", "securebank-sec", "securebank-obs"]
}

resource "kubernetes_namespace" "ns" {
  for_each = toset(var.namespaces)
  metadata {
    name = each.value
    labels = {
      "pod-security.kubernetes.io/enforce" = each.value == "securebank-obs" ? "baseline" : "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
      "securebank.local/tier"              = element(split("-", each.value), 1)
    }
  }
}

resource "kubernetes_resource_quota" "app_quota" {
  metadata {
    name      = "securebank-app-quota"
    namespace = "securebank-app"
  }
  spec {
    hard = {
      "requests.cpu"    = "4"
      "requests.memory" = "8Gi"
      "limits.cpu"      = "8"
      "limits.memory"   = "16Gi"
      "pods"            = "30"
    }
  }
  depends_on = [kubernetes_namespace.ns]
}

resource "kubernetes_network_policy" "default_deny" {
  for_each = toset(["securebank-app", "securebank-data", "securebank-sec"])
  metadata { name = "default-deny" namespace = each.value }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
  depends_on = [kubernetes_namespace.ns]
}
