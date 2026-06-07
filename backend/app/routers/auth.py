import re
import secrets
#import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_active_user, get_token_data
from app.models.user import TokenType, User, VerificationToken
from app.redis_client import get_redis
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from app.services import audit_service, session_service, token_service
from app.services.audit_service import AuditAction
from app.services.token_service import (
    blacklist_token,
    check_rate_limit,
    hash_refresh_token,
    increment_login_attempts,
    reset_login_attempts,
)

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Constants ─────────────────────────────────────────────────────────────────
ACCOUNT_LOCKOUT_THRESHOLD = 5       # failed attempts before lock
ACCOUNT_LOCKOUT_SECONDS   = 900     # 15 minutes


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _validate_password_strength(password: str) -> None:
    """
    Enforce minimum password policy:
      - 8+ characters
      - at least one uppercase letter
      - at least one lowercase letter
      - at least one digit
    """
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("at least one digit")
    if errors:
        raise HTTPException(
            status_code=422,
            detail=f"Password must contain: {', '.join(errors)}",
        )


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ── Register ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    _validate_password_strength(body.password)

    dup = await db.execute(
        select(User).where(
            (User.email == body.email) | (User.username == body.username)
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email or username already registered")

    user = User(
        email=body.email,
        username=body.username,
        hashed_password=_hash_password(body.password),
    )
    db.add(user)
    await db.flush()

    raw_token = secrets.token_urlsafe(32)
    db.add(VerificationToken(
        user_id=user.id,
        token=raw_token,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=_utcnow() + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
    ))

    await audit_service.log(
        db, AuditAction.USER_REGISTERED,
        target_id=user.id,
        ip_address=_get_ip(request),
        metadata={"email": user.email, "username": user.username},
    )

    return RegisterResponse(
        message="Registration successful. Use the verification_token to verify your email.",
        user=UserResponse.model_validate(user),
        verification_token=raw_token,
    )


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    ip = _get_ip(request)

    # ── 1. IP-based rate limit ─────────────────────────────────────────────
    is_blocked, info = await check_rate_limit(redis, ip)
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts from this IP. Try again in {info} seconds.",
        )

    # ── 2. Look up user ────────────────────────────────────────────────────
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user:
        # Log failed attempt without revealing whether email exists
        await increment_login_attempts(redis, ip)
        await audit_service.log(
            db, AuditAction.USER_LOGIN_FAILED,
            ip_address=ip,
            metadata={"email": body.email, "reason": "user_not_found"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # ── 3. Account-based lockout check ────────────────────────────────────
    if user.account_locked_until:
        locked_until = user.account_locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > _utcnow():
            remaining = int((locked_until - _utcnow()).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked due to too many failed attempts. Try again in {remaining} seconds.",
            )
        else:
            # Lock expired — reset
            user.account_locked_until = None
            user.failed_login_attempts = 0

    # ── 4. Verify password ─────────────────────────────────────────────────
    if not _verify_password(body.password, user.hashed_password):
        await increment_login_attempts(redis, ip)
        user.failed_login_attempts += 1

        await audit_service.log(
            db, AuditAction.USER_LOGIN_FAILED,
            target_id=user.id,
            ip_address=ip,
            metadata={"attempt": user.failed_login_attempts, "reason": "wrong_password"},
        )

        # Lock account if threshold reached
        if user.failed_login_attempts >= ACCOUNT_LOCKOUT_THRESHOLD:
            user.account_locked_until = _utcnow() + timedelta(seconds=ACCOUNT_LOCKOUT_SECONDS)
            await audit_service.log(
                db, AuditAction.ACCOUNT_LOCKED,
                target_id=user.id,
                ip_address=ip,
                metadata={
                    "locked_until": user.account_locked_until.isoformat(),
                    "failed_attempts": user.failed_login_attempts,
                },
            )
            # IMPORTANT: commit before raising — HTTPException triggers rollback
            # in get_db, so security state must be persisted first.
            await db.commit()
            raise HTTPException(
                status_code=403,
                detail=f"Account locked for {ACCOUNT_LOCKOUT_SECONDS // 60} minutes after too many failed attempts.",
            )

        # Persist incremented failure counter before the rollback from HTTPException
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # ── 5. Active check ────────────────────────────────────────────────────
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # ── 6. Success — clear counters, create session ────────────────────────
    await reset_login_attempts(redis, ip)
    user.failed_login_attempts = 0
    user.account_locked_until = None

    device_info = request.headers.get("User-Agent", "Unknown")
    session, raw_refresh = await session_service.create_session(
        user_id=user.id,
        device_info=device_info[:500],
        ip_address=ip,
        db=db,
        redis=redis,
    )

    access_token = token_service.create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
        session_id=session.id,
    )

    await audit_service.log(
        db, AuditAction.USER_LOGIN,
        actor_id=user.id,
        ip_address=ip,
        metadata={"session_id": str(session.id), "device": device_info[:100]},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout", response_model=MessageResponse)
async def logout(
    body: RefreshRequest,
    request: Request,
    token_data=Depends(get_token_data),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    await blacklist_token(redis, token_data.jti, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    refresh_hash = hash_refresh_token(body.refresh_token)
    await session_service.revoke_session_by_refresh_hash(refresh_hash, db, redis)

    await audit_service.log(
        db, AuditAction.USER_LOGOUT,
        actor_id=token_data.user_id,
        ip_address=_get_ip(request),
        metadata={"session_id": str(token_data.session_id)},
    )
    return MessageResponse(message="Logged out successfully")


# ── Refresh Tokens ────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """
    Rotate refresh token.
    If a revoked token is presented (reuse detected), the entire token family
    is invalidated — all sessions from that login chain are killed.
    """
    refresh_hash = hash_refresh_token(body.refresh_token)

    try:
        session, new_raw_refresh, reuse_detected = await session_service.rotate_refresh_token(
            old_token_hash=refresh_hash,
            db=db,
            redis=redis,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    if reuse_detected:
        # Commit family revocation BEFORE raising — HTTPException triggers rollback
        # in get_db's except block; we must persist the security response first.
        await audit_service.log(
            db, AuditAction.REFRESH_TOKEN_REUSE_DETECTED,
            ip_address=_get_ip(request),
            metadata={"token_hash_prefix": refresh_hash[:8]},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected. All sessions from this login have been revoked.",
        )

    result = await db.execute(select(User).where(User.id == session.user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")

    new_access = token_service.create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
        session_id=session.id,
    )
    return TokenResponse(
        access_token=new_access,
        refresh_token=new_raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ── Current User ──────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_active_user)):
    return UserResponse.model_validate(current_user)


# ── Email Verification ────────────────────────────────────────────────────────

@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    body: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(VerificationToken).where(
            VerificationToken.token == body.token,
            VerificationToken.token_type == TokenType.EMAIL_VERIFICATION,
            VerificationToken.is_used == False,  # noqa: E712
        )
    )
    vtoken = result.scalar_one_or_none()
    if not vtoken:
        raise HTTPException(status_code=400, detail="Invalid or already used token")

    now = _utcnow()
    expires_at = vtoken.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(status_code=400, detail="Verification token has expired")

    vtoken.is_used = True
    await db.execute(update(User).where(User.id == vtoken.user_id).values(is_verified=True))

    await audit_service.log(db, AuditAction.USER_EMAIL_VERIFIED, target_id=vtoken.user_id)
    return MessageResponse(message="Email verified successfully")


@router.post("/resend-verification", response_model=ForgotPasswordResponse)
async def resend_verification(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or user.is_verified:
        return ForgotPasswordResponse(
            message="If the email exists and is unverified, a new token has been issued.",
            reset_token="",
        )

    raw_token = secrets.token_urlsafe(32)
    db.add(VerificationToken(
        user_id=user.id,
        token=raw_token,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=_utcnow() + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
    ))
    return ForgotPasswordResponse(message="New verification token issued.", reset_token=raw_token)


# ── Password Reset ────────────────────────────────────────────────────────────

@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user:
        return ForgotPasswordResponse(
            message="If that email is registered, a reset token has been issued.",
            reset_token="",
        )

    raw_token = secrets.token_urlsafe(32)
    db.add(VerificationToken(
        user_id=user.id,
        token=raw_token,
        token_type=TokenType.PASSWORD_RESET,
        expires_at=_utcnow() + timedelta(hours=settings.PASSWORD_RESET_EXPIRE_HOURS),
    ))
    await audit_service.log(
        db, AuditAction.USER_PASSWORD_RESET_REQUESTED,
        target_id=user.id,
        ip_address=_get_ip(request),
    )
    return ForgotPasswordResponse(message="Password reset token issued.", reset_token=raw_token)


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    _validate_password_strength(body.new_password)
    result = await db.execute(
        select(VerificationToken).where(
            VerificationToken.token == body.token,
            VerificationToken.token_type == TokenType.PASSWORD_RESET,
            VerificationToken.is_used == False,  # noqa: E712
        )
    )
    vtoken = result.scalar_one_or_none()
    if not vtoken:
        raise HTTPException(status_code=400, detail="Invalid or already used token")

    now = _utcnow()
    expires_at = vtoken.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(status_code=400, detail="Reset token has expired")

    vtoken.is_used = True
    await db.execute(
        update(User).where(User.id == vtoken.user_id)
        .values(hashed_password=_hash_password(body.new_password))
    )
    await audit_service.log(db, AuditAction.USER_PASSWORD_RESET, target_id=vtoken.user_id)
    return MessageResponse(message="Password reset successfully")


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    _validate_password_strength(body.new_password)
    if not _verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    await db.execute(
        update(User).where(User.id == current_user.id)
        .values(hashed_password=_hash_password(body.new_password))
    )
    await audit_service.log(
        db, AuditAction.USER_PASSWORD_CHANGED,
        actor_id=current_user.id,
        ip_address=_get_ip(request),
    )
    return MessageResponse(message="Password changed successfully")
