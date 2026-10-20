"""Dependencias compartidas: autenticación, RBAC, paginación e idempotencia."""
from __future__ import annotations

import hmac
import uuid
from collections.abc import Callable

import jwt
from fastapi import Depends, Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_db
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized(detail: str = "No autenticado") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Token de acceso requerido")
    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except jwt.ExpiredSignatureError as exc:
        raise _unauthorized("La sesión ha expirado") from exc
    except jwt.InvalidTokenError as exc:
        raise _unauthorized("Token inválido") from exc

    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except Exception as exc:  # pragma: no cover - payload corrupto
        raise _unauthorized("Token inválido") from exc

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise _unauthorized("Usuario inactivo o inexistente")
    request.state.current_user = user
    return user


def require_permissions(*required: str) -> Callable:
    """Fábrica de dependencias RBAC. El rol admin conserva acceso total."""
    required_set = set(required)

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role.name == "admin":
            return user
        missing = required_set - user.permission_codes
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permisos insuficientes: {', '.join(sorted(missing))}",
            )
        return user

    return dependency


def verify_ingest_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.ingest_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key de ingesta inválida",
        )


class Pagination:
    def __init__(
        self,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> None:
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size
