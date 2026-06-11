from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_name: str = "ai-security-agent"
    bind_host: str = "0.0.0.0"
    bind_port: int = 8007

    # Optional LLM backend.  If unset, the agent falls back to its
    # deterministic heuristic reasoner so the service still works
    # in air-gapped lab/exam environments.
    llm_provider: str = Field("heuristic", alias="SB_LLM_PROVIDER")  # heuristic | anthropic | openai
    llm_model:    str = Field("claude-haiku-4-5-20251001", alias="SB_LLM_MODEL")
    llm_api_key:  str | None = Field(None, alias="SB_LLM_API_KEY")

    # Where to find platform clients
    fraud_model_path: str = "/var/lib/securebank/models/fraud_isoforest.joblib"
    feature_store_url: str = "http://feature-store.securebank-data:8080"

    class Config:
        env_prefix = "SB_"
        case_sensitive = False
