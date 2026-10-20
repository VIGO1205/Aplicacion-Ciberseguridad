"""Exporta el esquema SQLAlchemy a PostgreSQL DDL para db/init/01_schema.sql."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from app import models  # noqa: F401
from app.db.session import Base

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "db" / "init" / "01_schema.sql"


def main() -> None:
    dialect = postgresql.dialect()
    lines = [
        "-- SOC-Lite · Esquema PostgreSQL 15+",
        "-- Generado desde los modelos SQLAlchemy. No editar a mano sin actualizar modelos.",
        "",
        "BEGIN;",
        "",
    ]
    for table in Base.metadata.sorted_tables:
        lines.append(str(CreateTable(table).compile(dialect=dialect)).strip() + ";")
        lines.append("")
        for index in table.indexes:
            lines.append(str(CreateIndex(index).compile(dialect=dialect)).strip() + ";")
        lines.append("")

    lines.extend(
        [
            "COMMIT;",
            "",
            "-- Datos semilla: la aplicación los carga de forma idempotente al iniciar",
            "-- con AUTO_SEED=true o mediante: python -m app.seed",
            "",
        ]
    )
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text("\n".join(lines), encoding="utf-8")
    print(f"Esquema generado en {TARGET}")


if __name__ == "__main__":
    main()
