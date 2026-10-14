from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["local", "test", "production"] = "local"
    database_url: str = "sqlite:///./governance.db"
    jwt_secret: str = Field(default="local-only-change-me-32-characters", min_length=32)
    jwt_issuer: str = "secure-ai-governance"
    jwt_ttl_minutes: int = 60
    graph_provider: Literal["local", "microsoft"] = "local"
    ai_provider: Literal["mock", "ollama"] = "mock"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"
    approval_ttl_minutes: int = 30
    cache_ttl_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()
