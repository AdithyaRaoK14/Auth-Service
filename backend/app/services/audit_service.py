"""
Audit service — write-only log of every security-sensitive action.

Design: AuditLog rows are never updated or deleted.
Every call to `log()` inserts a row inside the *caller's* transaction,
so the audit record and the action it describes commit atomically.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import AuditLog


# ── Action constants (use these everywhere to avoid magic strings) ─────────────

class AuditAction:
    # Auth
    USER_REGISTERED = "USER_REGISTERED"
    USER_LOGIN = "USER_LOGIN"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    USER_LOGOUT = "USER_LOGOUT"
    USER_EMAIL_VERIFIED = "USER_EMAIL_VERIFIED"
    USER_PASSWORD_RESET_REQUESTED = "USER_PASSWORD_RESET_REQUESTED"
    USER_PASSWORD_RESET = "USER_PASSWORD_RESET"
    USER_PASSWORD_CHANGED = "USER_PASSWORD_CHANGED"

    # Account lockout
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"

    # Sessions
    SESSION_REVOKED = "SESSION_REVOKED"
    SESSION_ALL_REVOKED = "SESSION_ALL_REVOKED"

    # Refresh token security
    REFRESH_TOKEN_REUSE_DETECTED = "REFRESH_TOKEN_REUSE_DETECTED"

    # Admin — user management
    ADMIN_ROLE_CHANGED = "ADMIN_ROLE_CHANGED"
    ADMIN_USER_DELETED = "ADMIN_USER_DELETED"
    ADMIN_USER_DISABLED = "ADMIN_USER_DISABLED"
    ADMIN_USER_ENABLED = "ADMIN_USER_ENABLED"

    # Admin — permissions
    ADMIN_PERMISSION_GRANTED = "ADMIN_PERMISSION_GRANTED"
    ADMIN_PERMISSION_REVOKED = "ADMIN_PERMISSION_REVOKED"


# ── Write ──────────────────────────────────────────────────────────────────────

async def log(
    db: AsyncSession,
    action: str,
    actor_id: Optional[uuid.UUID] = None,
    target_id: Optional[uuid.UUID] = None,
    metadata: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Insert an audit log entry into the current DB transaction.
    Does NOT commit — the caller's transaction commits it alongside the action.
    """
    entry = AuditLog(
        actor_user_id=actor_id,
        target_user_id=target_id,
        action=action,
        metadata_=metadata,
        ip_address=ip_address,
    )
    db.add(entry)


# ── Read ───────────────────────────────────────────────────────────────────────

async def get_audit_logs(
    db: AsyncSession,
    action: Optional[str] = None,
    actor_id: Optional[uuid.UUID] = None,
    target_id: Optional[uuid.UUID] = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[AuditLog], int]:
    """
    Paginated audit log query with optional filters.
    Returns (rows, total_count).
    """
    query = select(AuditLog)

    if action:
        query = query.where(AuditLog.action == action)
    if actor_id:
        query = query.where(AuditLog.actor_user_id == actor_id)
    if target_id:
        query = query.where(AuditLog.target_user_id == target_id)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar_one()

    offset = (page - 1) * limit
    query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    rows = result.scalars().all()

    return rows, total
