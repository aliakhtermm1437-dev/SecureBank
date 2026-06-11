"""SOAR settings loaded from environment via Pydantic.

Secrets are projected into the pod from HashiCorp Vault via the agent
sidecar; nothing sensitive lives in the YAML manifests.
"""
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_name: str = "soar-service"
    bind_host: str = "0.0.0.0"
    bind_port: int = 8006

    # QRadar callback signature
    qradar_webhook_secret: str = Field(..., alias="SB_QRADAR_WEBHOOK_SECRET")

    # Where to call the rest of the platform
    auth_service_url:     str = "http://auth-service.securebank-app:8001"
    account_service_url:  str = "http://account-service.securebank-app:8002"
    gateway_url:          str = "http://api-gateway.securebank-edge:8000"

    # Redis used for idempotency & playbook state
    redis_url: str = "redis://redis.securebank-data:6379/4"

    # K8s in-cluster client uses the SA token by default; this overrides for tests
    kubeconfig_path: str | None = None

    # If true, playbooks log what they WOULD do without performing destructive ops
    dry_run: bool = False

    # Slack / pager webhook (HTTPS allow-list enforced by url_safety)
    pager_webhook_url: str | None = None

    class Config:
        env_prefix = "SB_"
        case_sensitive = False
