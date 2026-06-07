import uuid
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, EmailStr, field_validator


# ── Auth Schemas ──────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (underscores/hyphens allowed)")
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Username must be 3–50 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Token Schemas ─────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: uuid.UUID
    email: str
    role: str
    session_id: uuid.UUID
    jti: str


# ── User Schemas ──────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    is_verified: bool
    failed_login_attempts: int = 0
    account_locked_until: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SessionResponse(BaseModel):
    id: uuid.UUID
    device_info: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    last_active: datetime
    is_active: bool

    model_config = {"from_attributes": True}


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class UpdateRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in ("admin", "manager", "user"):
            raise ValueError("Role must be admin, manager, or user")
        return v


class GrantPermissionRequest(BaseModel):
    permission: str


class PermissionResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]

    model_config = {"from_attributes": True}


class UserDetailResponse(UserResponse):
    permissions: List[str] = []


# ── Pagination ────────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    pages: int
    limit: int


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: int
    actor_user_id: Optional[uuid.UUID]
    target_user_id: Optional[uuid.UUID]
    action: str
    metadata_: Optional[dict] = None
    ip_address: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Generic ───────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class RegisterResponse(BaseModel):
    message: str
    user: UserResponse
    verification_token: str


class ForgotPasswordResponse(BaseModel):
    message: str
    reset_token: str
