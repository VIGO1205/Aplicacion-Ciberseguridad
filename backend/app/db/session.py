"""Motor, sesión y base declarativa de SQLAlchemy."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _engine_kwargs(url: str) -> dict:
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update({"pool_size": 10, "max_overflow": 20, "pool_recycle": 1800})
    return kwargs


engine = create_engine(settings.database_url, **_engine_kwargs(settings.database_url))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Crea las tablas. En producción las migraciones se gestionan con Alembic."""
    from app import models  # noqa: F401  (registra los modelos en Base.metadata)

    if engine.dialect.name != "postgresql":
        Base.metadata.create_all(bind=engine)
        return

    # Uvicorn usa varios workers y el sincronizador también inicializa modelos.
    # Serializar el DDL evita que ambos creen la misma tabla a la vez.
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(50715901)"))
        try:
            Base.metadata.create_all(bind=connection)
            connection.commit()
        finally:
            if connection.in_transaction():
                connection.rollback()
            connection.execute(text("SELECT pg_advisory_unlock(50715901)"))
            connection.commit()
