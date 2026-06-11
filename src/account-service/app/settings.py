from securebank_shared.config import BaseServiceSettings


class AccountSettings(BaseServiceSettings):
    service_name: str = "account-service"
    bind_port: int = 8002

    jwt_issuer: str = "https://auth.securebank.local"
    jwt_audience: str = "https://api.securebank.local"
    jwks_url: str = "http://auth-service:8001/v1/auth/.well-known/jwks.json"


settings = AccountSettings()  # type: ignore[call-arg]
