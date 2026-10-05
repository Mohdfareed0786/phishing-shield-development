from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', case_sensitive=False)

    app_name: str = 'Phishing Shield API'
    environment: str = 'development'
    supabase_url: str = ''
    supabase_publishable_key: str = ''
    supabase_anon_key: str = ''
    cors_origins: str = 'http://localhost:3000'
    virus_total_api_key: str = ''
    google_safe_browsing_api_key: str = ''
    urlhaus_auth_key: str = ''
    abuse_ipdb_api_key: str = ''
    provider_timeout_seconds: float = 8.0
    max_request_bytes: int = 49152
    scan_rate_limit: int = 20
    scan_rate_window_seconds: int = 60

    @property
    def supabase_api_key(self) -> str:
        return self.supabase_publishable_key or self.supabase_anon_key

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip().rstrip('/') for origin in self.cors_origins.split(',') if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == 'production'


@lru_cache

def get_settings() -> Settings:
    return Settings()


settings = get_settings()
