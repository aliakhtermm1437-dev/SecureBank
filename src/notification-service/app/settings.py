from securebank_shared.config import BaseServiceSettings


class NotifySettings(BaseServiceSettings):
    service_name: str = "notification-service"
    bind_port: int = 8005
    kafka_topic_tx: str = "tx.transfers.v1"
    kafka_topic_alerts: str = "tx.fraud_alerts.v1"
    kafka_group_id: str = "notification-v1"
    # SMTP / SMS provider stubs — not exercised in academic demo.
    smtp_host: str = "smtp:1025"
    sms_provider_url: str = "http://sms-stub:9000/send"


settings = NotifySettings()  # type: ignore[call-arg]
