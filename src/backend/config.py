"""
Application configuration — reads from environment variables via Pydantic Settings.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="src/.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./infinity_threat.db"
    bob_api_key: str = ""
    bob_mcp_url: str = "http://localhost:8001"
    api_key: str = "dev-key-infinity"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    log_level: str = "INFO"
    feed_seed: int | None = None
    app_env: str = "development"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
