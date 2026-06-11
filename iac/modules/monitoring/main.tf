terraform {
  required_providers {
    helm = { source = "hashicorp/helm" }
  }
}

resource "helm_release" "kube_prom_stack" {
  name             = "prom-stack"
  namespace        = "securebank-obs"
  create_namespace = true
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  version          = "62.6.0"
  values = [file("${path.module}/values-prom.yaml")]
}

resource "helm_release" "loki" {
  name       = "loki"
  namespace  = "securebank-obs"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki-stack"
  version    = "2.10.2"
}

resource "helm_release" "falco" {
  name       = "falco"
  namespace  = "falco"
  create_namespace = true
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = "4.2.5"
  set { name = "driver.kind" value = "ebpf" }
}
