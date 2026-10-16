from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["local", "test", "production"] = "local"
    database_url: str = "sqlite:///./governance.db"
    persistence_mode: Literal["memory", "database"] = "memory"
    jwt_secret: str = Field(default="local-only-change-me-32-characters", min_length=32)
    jwt_issuer: str = "secure-ai-governance"
    jwt_ttl_minutes: int = 60
    graph_provider: Literal["local", "microsoft"] = "local"
    identity_mode: Literal["local", "oidc"] = "local"
    oidc_issuer: str = "http://localhost:8080/realms/governance"
    oidc_audience: str = "governance-api"
    oidc_jwks_url: str | None = None
    policy_provider: Literal["local", "opa"] = "local"
    opa_url: str = "http://localhost:8181/v1/data/governance/dlp/decision"
    classifier_provider: Literal["local", "presidio"] = "local"
    presidio_url: str = "http://localhost:5001"
    ai_provider: Literal["mock", "ollama"] = "mock"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"
    rag_mode: Literal["local", "postgres"] = "local"
    embedding_provider: Literal["hash", "ollama"] = "hash"
    embedding_model: str = "nomic-embed-text"
    embedding_dimensions: int = 768
    approval_ttl_minutes: int = 30
    cache_ttl_seconds: int = 300
    opensearch_url: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
