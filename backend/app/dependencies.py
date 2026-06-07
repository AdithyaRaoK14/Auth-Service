import uuid
from typing import List

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import Permission, User, UserPermission
from app.redis_client import get_redis
from app.schemas.auth import TokenData
from app.services.token_service import is_token_blacklisted, verify_access_token

bearer_scheme = HTTPBearer()


# ─── Core Auth Dependency ─────────────────────────────────────────────────────

async def get_token_data(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    redis: aioredis.Redis = Depends(get_redis),
) -> TokenData:
    """Extract and validate JWT from Authorization header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_data = verify_access_token(credentials.credentials)
    except JWTError:
        raise credentials_exception

    # Check blacklist
    if await is_token_blacklisted(redis, token_data.jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


async def get_current_user(
    token_data: TokenData = Depends(get_token_data),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Load full User object from token claims."""
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    return current_user


# ─── RBAC Decorator ───────────────────────────────────────────────────────────

def require_role(*roles: str):
    """
    FastAPI dependency factory for role-based access control.

    Usage:
        @router.get("/admin/users")
        async def list_users(current_user: User = require_role("admin")):
            ...

        @router.get("/reports")
        async def get_reports(current_user: User = require_role("admin", "manager")):
            ...
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if current_user.role.value not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {', '.join(roles)}",
            )
        return current_user

    return Depends(role_checker)


# ─── Permission Checker ───────────────────────────────────────────────────────

def require_permission(permission_name: str):
    """
    FastAPI dependency factory for fine-grained permission checks.
    Admins bypass all permission checks.

    Usage:
        @router.get("/reports")
        async def view_reports(
            current_user: User = require_permission("read_reports")
        ):
            ...
    """
    async def permission_checker(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        # Admins have all permissions
        if current_user.role.value == "admin":
            return current_user

        # Check explicit permission grant
        result = await db.execute(
            select(UserPermission)
            .join(Permission, UserPermission.permission_id == Permission.id)
            .where(
                UserPermission.user_id == current_user.id,
                Permission.name == permission_name,
            )
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission_name}",
            )
        return current_user

    return Depends(permission_checker)


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def get_user_permission_names(
    user_id: uuid.UUID, db: AsyncSession
) -> List[str]:
    """Return list of permission name strings for a user."""
    result = await db.execute(
        select(Permission.name)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user_id)
    )
    return [row[0] for row in result.fetchall()]
