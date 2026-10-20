"""Primitivas de seguridad: hashing, JWT y utilidades de petición."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Request

from app.core.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _base_claims(user_id: str, email: str, role: str, token_type: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": token_type,
        "iat": now,
        "jti": uuid.uuid4().hex,
    }


def create_access_token(user_id: str, email: str, role: str) -> tuple[str, int]:
    expires_in = settings.access_token_expire_minutes * 60
    claims = _base_claims(user_id, email, role, "access")
    claims["exp"] = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    return jwt.encode(claims, settings.secret_key, algorithm=settings.jwt_algorithm), expires_in


def create_refresh_token(user_id: str, email: str, role: str) -> tuple[str, str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    claims = _base_claims(user_id, email, role, "refresh")
    claims["exp"] = expires_at
    token = jwt.encode(claims, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, claims["jti"], expires_at


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Tipo de token inválido")
    return payload


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    if request.client:
        return request.client.host[:45]
    return None


def ensure_aware(value: datetime | None) -> datetime | None:
    """SQLite devuelve datetimes naive; se normalizan a UTC para los cálculos."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def password_is_strong(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "La contraseña debe tener al menos 10 caracteres"
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe incluir al menos una mayúscula"
    if not any(c.islower() for c in password):
        return False, "La contraseña debe incluir al menos una minúscula"
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe incluir al menos un número"
    return True, ""
