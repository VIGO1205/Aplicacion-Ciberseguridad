"""Administración de usuarios, roles y permisos (RBAC)."""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import Pagination, get_current_user, require_permissions
from app.core.security import client_ip, hash_password, password_is_strong
from app.db.session import get_db
from app.models import Permission, RefreshToken, Role, User
from app.schemas import (
    Message,
    PasswordReset,
    PermissionOut,
    RoleOut,
    UserBrief,
    UserCreate,
    UserOut,
    UserPage,
    UserUpdate,
)
from app.services.audit import record_audit

router = APIRouter(tags=["Usuarios y roles"])


@router.get("/users", response_model=UserPage, summary="Listar usuarios")
def list_users(
    pagination: Pagination = Depends(),
    q: str | None = Query(default=None, max_length=120),
    active: bool | None = None,
    role_id: uuid.UUID | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("users:read")),
) -> UserPage:
    conditions = []
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            or_(
                User.full_name.ilike(needle),
                User.email.ilike(needle),
                User.department.ilike(needle),
            )
        )
    if active is not None:
        conditions.append(User.is_active == active)
    if role_id:
        conditions.append(User.role_id == role_id)
    count_stmt = select(func.count(User.id))
    stmt = select(User)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
        stmt = stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0
    users = list(
        db.scalars(
            stmt.order_by(User.full_name.asc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        ).all()
    )
    return UserPage(
        items=[UserOut.model_validate(user) for user in users],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(total / pagination.page_size) if total else 0,
    )


@router.get("/users/assignable", response_model=list[UserBrief], summary="Usuarios asignables")
def assignable_users(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[UserBrief]:
    allowed = {"users:read", "alerts:update", "incidents:update"}
    if user.role.name != "admin" and not (user.permission_codes & allowed):
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    users = list(db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.full_name)).all())
    return [UserBrief.model_validate(item) for item in users]


@router.get("/users/{user_id}", response_model=UserOut, summary="Detalle de usuario")
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("users:read")),
) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return UserOut.model_validate(user)


@router.post("/users", response_model=UserOut, status_code=201, summary="Crear usuario")
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permissions("users:manage")),
) -> UserOut:
    email = payload.email.lower()
    if db.scalar(select(User).where(func.lower(User.email) == email)):
        raise HTTPException(status_code=409, detail="Ya existe un usuario con ese correo")
    role = db.get(Role, payload.role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Rol no encontrado")
    valid, message = password_is_strong(payload.password)
    if not valid:
        raise HTTPException(status_code=422, detail=message)

    user = User(
        email=email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role_id=role.id,
        job_title=payload.job_title,
        department=payload.department,
        phone=payload.phone,
        is_active=True,
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        module="users",
        action="Creación de usuario",
        event_type="CREATE",
        user=actor,
        entity_type="user",
        entity_id=user.id,
        description=f"{user.full_name} <{user.email}> · rol {role.name}",
        method="POST",
        path="/api/v1/users",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut, summary="Actualizar usuario")
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permissions("users:manage")),
) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    changes = payload.model_dump(exclude_unset=True)
    if user.id == actor.id and changes.get("is_active") is False:
        raise HTTPException(status_code=400, detail="No puede desactivar su propia cuenta")
    if "role_id" in changes:
        role = db.get(Role, changes["role_id"])
        if role is None:
            raise HTTPException(status_code=404, detail="Rol no encontrado")
    for field, value in changes.items():
        setattr(user, field, value)
    record_audit(
        db,
        module="users",
        action="Actualización de usuario",
        event_type="UPDATE",
        user=actor,
        entity_type="user",
        entity_id=user.id,
        description=f"Campos actualizados: {', '.join(changes.keys())}",
        detail={"changes": {key: str(value) for key, value in changes.items()}},
        method="PATCH",
        path=f"/api/v1/users/{user_id}",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/reset-password", response_model=Message, summary="Restablecer contraseña")
def reset_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_permissions("users:manage")),
) -> Message:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    valid, message = password_is_strong(payload.new_password)
    if not valid:
        raise HTTPException(status_code=422, detail=message)
    user.hashed_password = hash_password(payload.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    db.execute(delete(RefreshToken).where(RefreshToken.user_id == user.id))
    record_audit(
        db,
        module="users",
        action="Restablecimiento de contraseña",
        event_type="UPDATE",
        user=actor,
        entity_type="user",
        entity_id=user.id,
        description=f"Contraseña restablecida para {user.email}",
        method="POST",
        path=f"/api/v1/users/{user_id}/reset-password",
        ip_address=client_ip(request),
    )
    db.commit()
    return Message(message="Contraseña restablecida")


@router.get("/roles", response_model=list[RoleOut], summary="Listar roles y permisos")
def list_roles(
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("users:read")),
) -> list[RoleOut]:
    roles = list(db.scalars(select(Role).order_by(Role.name)).all())
    return [RoleOut.model_validate(role) for role in roles]


@router.get("/permissions", response_model=list[PermissionOut], summary="Listar permisos")
def list_permissions(
    db: Session = Depends(get_db),
    _: User = Depends(require_permissions("users:read")),
) -> list[PermissionOut]:
    return [PermissionOut.model_validate(item) for item in db.scalars(select(Permission).order_by(Permission.module, Permission.code)).all()]
