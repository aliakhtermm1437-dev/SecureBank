from securebank_shared.config import BaseServiceSettings


class FraudSettings(BaseServiceSettings):
    service_name: str = "fraud-detection-service"
    bind_port: int = 8004
    kafka_topic_in: str = "tx.transfers.v1"
    kafka_topic_out: str = "tx.fraud_alerts.v1"
    kafka_group_id: str = "fraud-detection-v1"
    model_path: str = "/var/lib/securebank/fraud_iforest.joblib"
    score_threshold: float = 0.7
    drift_window: int = 1000


settings = FraudSettings()  # type: ignore[call-arg]
