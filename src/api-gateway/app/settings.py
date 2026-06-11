from pydantic import Field
from securebank_shared.config import BaseServiceSettings


class GatewaySettings(BaseServiceSettings):
    service_name: str = "api-gateway"
    bind_port: int = 8443

    jwt_issuer: str = "https://auth.securebank.local"
    jwt_audience: str = "https://api.securebank.local"
    jwks_url: str = "http://auth-service:8001/v1/auth/.well-known/jwks.json"

    upstream_auth: str = "http://auth-service:8001"
    upstream_account: str = "http://account-service:8002"
    upstream_tx: str = "http://transaction-service:8003"
    upstream_notification: str = "http://notification-service:8005"

    anon_rate_per_min: int = 100
    auth_rate_per_min: int = 1000

    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])


settings = GatewaySettings()  # type: ignore[call-arg]
