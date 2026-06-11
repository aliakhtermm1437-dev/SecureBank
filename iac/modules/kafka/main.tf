terraform {
  required_providers { kafka = { source = "Mongey/kafka" } }
}

resource "kafka_topic" "transfers" {
  name               = "tx.transfers.v1"
  replication_factor = 3
  partitions         = 6
  config = {
    "min.insync.replicas" = "2"
    "retention.ms"        = "604800000"  # 7d
    "cleanup.policy"      = "delete"
    "compression.type"    = "producer"
  }
}

resource "kafka_topic" "fraud_alerts" {
  name               = "tx.fraud_alerts.v1"
  replication_factor = 3
  partitions         = 6
  config = {
    "min.insync.replicas" = "2"
    "retention.ms"        = "1209600000" # 14d
  }
}
