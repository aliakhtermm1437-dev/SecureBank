"""Centralised typed configuration loader.

Every service should subclass :class:`BaseServiceSettings`. Secrets are NEVER
read from environment variables in production — they are fetched from Vault via
:class:`securebank_shared.vault.VaultClient`. Env-vars hold only pointers and
non-secret config (URLs, ports, log level, etc.).
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=None,
        env_prefix="SB_",
        extra="ignore",
        case_sensitive=False,
    )

    service_name: str = Field(..., description="Logical service name, e.g. auth-service")
    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = True

    # Networking
    bind_host: str = "0.0.0.0"  # noqa: S104 -- bound inside container netns; ingress restricted
    bind_port: int = 8000

    # TLS / mTLS — paths to materials projected from Vault PKI
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
    tls_ca_path: str | None = None
    require_mtls: bool = True

    # Backends — non-secret connection details only
    postgres_dsn: str | None = None  # password injected at runtime via Vault
    redis_url: str | None = None
    kafka_bootstrap: str | None = None

    # Vault
    vault_addr: str = "http://vault:8200"
    vault_role: str | None = None  # AppRole role-id supplied via projected token

    # Observability
    otel_endpoint: str = "http://otel-collector:4317"
    metrics_path: str = "/metrics"

    # Feature flags
    demo_seed: bool = False
