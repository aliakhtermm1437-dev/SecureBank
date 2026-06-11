from __future__ import annotations

from pydantic import Field

from securebank_shared.config import BaseServiceSettings


class AuthSettings(BaseServiceSettings):
    service_name: str = "auth-service"
    bind_port: int = 8001

    jwt_issuer: str = "https://auth.securebank.local"
    jwt_audience: str = "https://api.securebank.local"
    jwt_access_ttl_s: int = 900
    jwt_refresh_ttl_s: int = 7 * 24 * 3600

    # Vault paths
    vault_kv_path: str = "auth/keys"
    vault_transit_session_key: str = "session-encryption"
    vault_pki_role: str = "auth-service"

    # Rate limits
    login_rate_per_min: int = 5
    register_rate_per_min: int = 10
    mfa_verify_max_attempts: int = 10

    # HIBP API
    hibp_enabled: bool = True

    cors_origins: list[str] = Field(default_factory=lambda: ["https://app.securebank.local"])
    trusted_hosts: list[str] = Field(default_factory=lambda: ["*"])  # gateway enforces


settings = AuthSettings()  # type: ignore[call-arg]
