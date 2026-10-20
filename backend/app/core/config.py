"""Configuración central de SOC-Lite.

Todos los valores se pueden sobreescribir con variables de entorno o con un
archivo .env situado en la raíz del repositorio.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", PROJECT_ROOT / "backend" / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SOC-Lite"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # --- Seguridad ---------------------------------------------------------
    secret_key: str = "cambia-esta-clave-en-produccion-32-caracteres-minimo"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    refresh_token_expire_days: int = 7
    login_max_attempts: int = 5
    login_lock_minutes: int = 15

    # --- Base de datos -----------------------------------------------------
    database_url: str = (
        "postgresql+psycopg://soc_lite:soc_lite_dev_password@localhost:5432/soc_lite"
    )
    auto_seed: bool = False

    # --- Integraciones -----------------------------------------------------
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    ingest_api_key: str = "dev-ingest-key-cambiar"
    triage_service_url: str = "http://localhost:8001"
    triage_api_key: str = ""
    triage_timeout_seconds: float = 45.0
    # auto: intenta el microservicio y cae al motor heurístico local.
    triage_mode: str = "auto"  # auto | remote | heuristic

    # --- Reportes ----------------------------------------------------------
    reports_dir: Path = PROJECT_ROOT / "storage" / "reports"
    report_brand: str = "SOC-Lite · Centro de Operaciones de Seguridad"

    # --- Operación ---------------------------------------------------------
    timezone: str = "America/Lima"
    demo_mode: bool = True
    log_level: str = "INFO"

    @field_validator("cors_origins")
    @classmethod
    def _strip_origins(cls, value: str) -> str:
        return ",".join(item.strip() for item in value.split(",") if item.strip())

    @property
    def cors_origin_list(self) -> list[str]:
        return [item for item in self.cors_origins.split(",") if item]

    @property
    def reports_path(self) -> Path:
        path = Path(self.reports_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
