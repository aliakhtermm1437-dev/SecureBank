from pydantic import Field
from securebank_shared.config import BaseServiceSettings


class TxSettings(BaseServiceSettings):
    service_name: str = "transaction-service"
    bind_port: int = 8003

    jwt_issuer: str = "https://auth.securebank.local"
    jwt_audience: str = "https://api.securebank.local"
    jwks_url: str = "http://auth-service:8001/v1/auth/.well-known/jwks.json"

    account_service_url: str = "http://account-service:8002"

    kafka_topic_tx: str = "tx.transfers.v1"
    kafka_topic_fraud_alerts: str = "tx.fraud_alerts.v1"
    kafka_sasl_user: str | None = None
    kafka_sasl_pass: str | None = None
    kafka_ca: str | None = None
    kafka_cert: str | None = None
    kafka_key: str | None = None

    step_up_threshold_pkr: int = 10_000


settings = TxSettings()  # type: ignore[call-arg]
