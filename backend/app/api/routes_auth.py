"""Autenticación JWT, refresh tokens, bloqueo por intentos y cambio de clave."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    client_ip,
    create_access_token,
    create_refresh_token,
    decode_token,
    ensure_aware,
    hash_password,
    password_is_strong,
    verify_password,
)
from app.db.session import get_db
from app.api.deps import get_current_user
from app.models import RefreshToken, User
from app.schemas import (
    ChangePassword,
    LoginRequest,
    LogoutRequest,
    Message,
    RefreshRequest,
    TokenResponse,
    UserOut,
)
from app.services.audit import record_audit

router = APIRouter(prefix="/auth", tags=["Autenticación"])

_attempts: dict[str, list[datetime]] = defaultdict(list)


def _attempt_key(email: str, request: Request) -> str:
    return f"{email.lower()}|{client_ip(request) or 'sin-ip'}"


def _register_failure(key: str) -> None:
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=settings.login_lock_minutes)
    _attempts[key] = [item for item in _attempts[key] if item > window]
    _attempts[key].append(now)


def _is_locked(key: str) -> bool:
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=settings.login_lock_minutes)
    _attempts[key] = [item for item in _attempts[key] if item > window]
    return len(_attempts[key]) >= settings.login_max_attempts


def _issue_tokens(db: Session, user: User, request: Request) -> TokenResponse:
    access_token, expires_in = create_access_token(str(user.id), user.email, user.role.name)
    refresh_token, jti, expires_at = create_refresh_token(str(user.id), user.email, user.role.name)
    db.add(
        RefreshToken(
            user_id=user.id,
            jti=jti,
            expires_at=expires_at,
        )
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse, summary="Iniciar sesión")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    key = _attempt_key(payload.email, request)
    if _is_locked(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Demasiados intentos. Reintente en {settings.login_lock_minutes} minutos.",
        )

    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active or not verify_password(payload.password, user.hashed_password):
        _register_failure(key)
        record_audit(
            db,
            module="auth",
            action="Inicio de sesión fallido",
            event_type="LOGIN_FAILED",
            actor_email=payload.email.lower(),
            direction="IN",
            description="Credenciales inválidas o usuario inactivo",
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status_code=401,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _attempts.pop(key, None)
    user.last_login_at = datetime.now(timezone.utc)
    record_audit(
        db,
        module="auth",
        action="Inicio de sesión exitoso",
        event_type="LOGIN",
        user=user,
        direction="IN",
        description="Autenticación mediante correo y contraseña",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status_code=200,
    )
    response = _issue_tokens(db, user, request)
    db.commit()
    return response


@router.post("/refresh", response_model=TokenResponse, summary="Renovar token de acceso")
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Refresh token inválido o expirado") from exc

    stored = db.scalar(select(RefreshToken).where(RefreshToken.jti == claims.get("jti")))
    if stored is None or stored.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Refresh token revocado")
    if ensure_aware(stored.expires_at) and ensure_aware(stored.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    user = db.scalar(select(User).where(User.id == uuid.UUID(str(claims.get("sub")))))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario inactivo")

    stored.revoked_at = datetime.now(timezone.utc)
    response = _issue_tokens(db, user, request)
    record_audit(
        db,
        module="auth",
        action="Renovación de token",
        event_type="TOKEN_REFRESH",
        user=user,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status_code=200,
    )
    db.commit()
    return response


@router.post("/logout", response_model=Message, summary="Cerrar sesión")
def logout(
    payload: LogoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Message:
    if payload.refresh_token:
        try:
            claims = decode_token(payload.refresh_token, expected_type="refresh")
            db.execute(
                delete(RefreshToken).where(
                    RefreshToken.jti == claims.get("jti"), RefreshToken.user_id == current_user.id
                )
            )
        except jwt.InvalidTokenError:
            pass
    record_audit(
        db,
        module="auth",
        action="Cierre de sesión",
        event_type="LOGOUT",
        user=current_user,
        direction="OUT",
        description="Cierre de sesión voluntario",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status_code=200,
    )
    db.commit()
    return Message(message="Sesión cerrada")


@router.get("/me", response_model=UserOut, summary="Perfil del usuario autenticado")
def me(current_user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(current_user)


@router.post("/change-password", response_model=Message, summary="Cambiar contraseña")
def change_password(
    payload: ChangePassword,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Message:
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta")
    valid, message = password_is_strong(payload.new_password)
    if not valid:
        raise HTTPException(status_code=422, detail=message)

    current_user.hashed_password = hash_password(payload.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.execute(delete(RefreshToken).where(RefreshToken.user_id == current_user.id))
    record_audit(
        db,
        module="auth",
        action="Cambio de contraseña",
        event_type="PASSWORD_CHANGE",
        user=current_user,
        description="El usuario actualizó su contraseña; se revocaron sesiones previas",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    return Message(message="Contraseña actualizada. Inicie sesión nuevamente.")
