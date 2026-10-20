"""Configuración del microservicio de triaje LangChain."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class AISettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SOC-Lite Triage AI"
    app_version: str = "1.0.0"
    environment: str = "development"
    internal_api_key: str = ""

    # auto: intenta Ollama y, si falla, usa el motor heurístico.
    llm_provider: str = "auto"  # auto | ollama | openai | heuristic
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = ""

    enrichment_enabled: bool = True
    geoip_enabled: bool = False
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    http_timeout_seconds: float = 8.0
    max_description_chars: int = 6000
    prompt_version: str = "triage-v1"

    @property
    def has_external_enrichment(self) -> bool:
        return bool(
            self.virustotal_api_key or self.abuseipdb_api_key or self.geoip_enabled
        )


@lru_cache
def get_settings() -> AISettings:
    return AISettings()


settings = get_settings()
