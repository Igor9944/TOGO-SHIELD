from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "TOGO-SHIELD"
    database_url: str = "sqlite:///./togo_shield.db"
    jwt_secret_key: str = "change-me-in-production"
    jwt_expire_minutes: int = 30
    telegram_enabled: bool = False
    telegram_mode: str = "webhook"
    telegram_bot_token: str | None = None
    telegram_webhook_url: str | None = "https://togo-shield.vercel.app/api/telegram/webhook"
    telegram_webhook_secret: str | None = None
    virustotal_api_key: str | None = None
    urlhaus_api_key: str | None = None
    max_upload_size_mb: int = 4
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()