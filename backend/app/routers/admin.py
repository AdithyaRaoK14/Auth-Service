import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_user_permission_names, require_permission, require_role
from app.models.user import Permission, User, UserPermission, UserRole
from app.schemas.auth import (
    AuditLogResponse,
    GrantPermissionRequest,
    MessageResponse,
    PaginatedResponse,
    PermissionResponse,
    UpdateRoleRequest,
    UserDetailResponse,
    UserResponse,
)
from app.services import audit_service
from app.services.audit_service import AuditAction

router = APIRouter(prefix="/admin", tags=["admin"])

_admin_only = require_role("admin")


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ── User Management ───────────────────────────────────────────────────────────

@router.get("/users", response_model=PaginatedResponse)
async def list_users(
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    _: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    """List users with search, role filter, and pagination."""
    query = select(User)
    if search:
        query = query.where(
            (User.email.ilike(f"%{search}%")) | (User.username.ilike(f"%{search}%"))
        )
    if role:
        try:
            query = query.where(User.role == UserRole(role))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {role}")

    # Total count
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    offset = (page - 1) * limit
    query = query.offset(offset).limit(limit).order_by(User.created_at.desc())
    result = await db.execute(query)
    users = result.scalars().all()

    items = []
    for user in users:
        perms = await get_user_permission_names(user.id, db)
        items.append(UserDetailResponse(
            **UserResponse.model_validate(user).model_dump(),
            permissions=perms,
        ))

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        pages=(total + limit - 1) // limit,
        limit=limit,
    )


@router.get("/users/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: uuid.UUID,
    _: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    perms = await get_user_permission_names(user_id, db)
    return UserDetailResponse(**UserResponse.model_validate(user).model_dump(), permissions=perms)


@router.put("/users/{user_id}/role", response_model=MessageResponse)
async def update_user_role(
    user_id: uuid.UUID,
    body: UpdateRoleRequest,
    request: Request,
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role.value
    user.role = UserRole(body.role)

    await audit_service.log(
        db, AuditAction.ADMIN_ROLE_CHANGED,
        actor_id=admin.id, target_id=user_id,
        ip_address=_get_ip(request),
        metadata={"from": old_role, "to": body.role},
    )
    return MessageResponse(message=f"Role updated to '{body.role}'")


@router.put("/users/{user_id}/active", response_model=MessageResponse)
async def toggle_user_active(
    user_id: uuid.UUID,
    active: bool = Query(...),
    request: Request = None,
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = active
    action = AuditAction.ADMIN_USER_ENABLED if active else AuditAction.ADMIN_USER_DISABLED
    await audit_service.log(
        db, action,
        actor_id=admin.id, target_id=user_id,
        ip_address=_get_ip(request) if request else None,
    )
    return MessageResponse(message=f"User {'enabled' if active else 'disabled'}")


@router.delete("/users/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: uuid.UUID,
    request: Request,
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await audit_service.log(
        db, AuditAction.ADMIN_USER_DELETED,
        actor_id=admin.id, target_id=user_id,
        ip_address=_get_ip(request),
        metadata={"email": user.email, "username": user.username},
    )
    await db.delete(user)
    return MessageResponse(message="User deleted")


# ── Permission Management ─────────────────────────────────────────────────────

@router.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    _: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Permission).order_by(Permission.name))
    return result.scalars().all()


@router.post("/permissions", response_model=PermissionResponse, status_code=201)
async def create_permission(
    body: GrantPermissionRequest,
    _: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(Permission).where(Permission.name == body.permission))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Permission already exists")
    perm = Permission(name=body.permission)
    db.add(perm)
    await db.flush()
    return perm


@router.post("/users/{user_id}/permissions", response_model=MessageResponse)
async def grant_permission(
    user_id: uuid.UUID,
    body: GrantPermissionRequest,
    request: Request,
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(select(User).where(User.id == user_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")

    perm_result = await db.execute(select(Permission).where(Permission.name == body.permission))
    perm = perm_result.scalar_one_or_none()
    if not perm:
        perm = Permission(name=body.permission)
        db.add(perm)
        await db.flush()

    existing = await db.execute(
        select(UserPermission).where(
            UserPermission.user_id == user_id,
            UserPermission.permission_id == perm.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Permission already granted")

    db.add(UserPermission(user_id=user_id, permission_id=perm.id))
    await audit_service.log(
        db, AuditAction.ADMIN_PERMISSION_GRANTED,
        actor_id=admin.id, target_id=user_id,
        ip_address=_get_ip(request),
        metadata={"permission": body.permission},
    )
    return MessageResponse(message=f"Permission '{body.permission}' granted")


@router.delete("/users/{user_id}/permissions/{permission_name}", response_model=MessageResponse)
async def revoke_permission(
    user_id: uuid.UUID,
    permission_name: str,
    request: Request,
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    perm_result = await db.execute(select(Permission).where(Permission.name == permission_name))
    perm = perm_result.scalar_one_or_none()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    result = await db.execute(
        select(UserPermission).where(
            UserPermission.user_id == user_id,
            UserPermission.permission_id == perm.id,
        )
    )
    up = result.scalar_one_or_none()
    if not up:
        raise HTTPException(status_code=404, detail="Permission not granted to this user")

    await db.delete(up)
    await audit_service.log(
        db, AuditAction.ADMIN_PERMISSION_REVOKED,
        actor_id=admin.id, target_id=user_id,
        ip_address=_get_ip(request),
        metadata={"permission": permission_name},
    )
    return MessageResponse(message=f"Permission '{permission_name}' revoked")


# ── Audit Logs ────────────────────────────────────────────────────────────────

@router.get("/audit-logs", response_model=PaginatedResponse)
async def get_audit_logs(
    action: Optional[str] = Query(None),
    actor_id: Optional[uuid.UUID] = Query(None),
    target_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    admin: User = _admin_only,
    db: AsyncSession = Depends(get_db),
):
    """Paginated audit log with filters. Admin only."""
    rows, total = await audit_service.get_audit_logs(
        db=db, action=action, actor_id=actor_id,
        target_id=target_id, page=page, limit=limit,
    )

    items = [AuditLogResponse.model_validate(r) for r in rows]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        pages=(total + limit - 1) // limit,
        limit=limit,
    )


# ── Demo: permission-protected endpoint ──────────────────────────────────────

@router.get("/reports", response_model=MessageResponse)
async def view_reports(
    current_user: User = require_permission("read_reports"),
):
    """Example fine-grained permission check. Admins bypass automatically."""
    return MessageResponse(message=f"Reports accessed by {current_user.email}")
