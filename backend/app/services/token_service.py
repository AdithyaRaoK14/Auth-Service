import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from jose import JWTError, jwt

from app.config import settings
from app.schemas.auth import TokenData

# Redis key prefixes
BLACKLIST_PREFIX = "blacklist:jti:"
RATE_LIMIT_PREFIX = "rate_limit:login:"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─── JWT Access Tokens ────────────────────────────────────────────────────────

def create_access_token(
    user_id: uuid.UUID,
    email: str,
    role: str,
    session_id: uuid.UUID,
) -> str:
    """Create a short-lived JWT access token."""
    jti = str(uuid.uuid4())
    expire = _utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "session_id": str(session_id),
        "jti": jti,
        "exp": expire,
        "iat": _utcnow(),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_access_token(token: str) -> TokenData:
    """Decode and validate JWT. Raises JWTError on failure."""
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    if payload.get("type") != "access":
        raise JWTError("Not an access token")

    return TokenData(
        user_id=uuid.UUID(payload["sub"]),
        email=payload["email"],
        role=payload["role"],
        session_id=uuid.UUID(payload["session_id"]),
        jti=payload["jti"],
    )


def get_token_jti(token: str) -> str:
    """Extract JTI without full verification (used for blacklisting on logout)."""
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False},
    )
    return payload["jti"]


def get_token_remaining_ttl(token: str) -> int:
    """Return seconds until token expiry (for Redis TTL). Min 0."""
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_exp": False},
    )
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    remaining = int((exp - _utcnow()).total_seconds())
    return max(remaining, 0)


# ─── Refresh Tokens ───────────────────────────────────────────────────────────

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a cryptographically secure refresh token.
    Returns (raw_token, hashed_token). Only hash is stored in DB.
    """
    raw = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash


def hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    return _utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)


# ─── Token Blacklist (Redis) ──────────────────────────────────────────────────

async def blacklist_token(redis: aioredis.Redis, jti: str, ttl_seconds: int) -> None:
    """Add JTI to Redis blacklist with TTL matching token expiry."""
    if ttl_seconds > 0:
        await redis.setex(f"{BLACKLIST_PREFIX}{jti}", ttl_seconds, "1")


async def is_token_blacklisted(redis: aioredis.Redis, jti: str) -> bool:
    result = await redis.get(f"{BLACKLIST_PREFIX}{jti}")
    return result is not None


# ─── Rate Limiting ────────────────────────────────────────────────────────────

async def check_rate_limit(redis: aioredis.Redis, ip: str) -> tuple[bool, int]:
    """
    Check if IP is rate limited for login attempts.
    Returns (is_blocked, remaining_attempts).
    """
    key = f"{RATE_LIMIT_PREFIX}{ip}"
    current = await redis.get(key)

    if current is None:
        return False, settings.LOGIN_MAX_ATTEMPTS

    count = int(current)
    if count >= settings.LOGIN_MAX_ATTEMPTS:
        ttl = await redis.ttl(key)
        return True, ttl  # returning block TTL instead of attempts

    return False, settings.LOGIN_MAX_ATTEMPTS - count


async def increment_login_attempts(redis: aioredis.Redis, ip: str) -> int:
    """Increment failed login counter. Sets expiry on first attempt."""
    key = f"{RATE_LIMIT_PREFIX}{ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, settings.LOGIN_BLOCK_SECONDS)
    return count


async def reset_login_attempts(redis: aioredis.Redis, ip: str) -> None:
    """Clear rate limit counter after successful login."""
    await redis.delete(f"{RATE_LIMIT_PREFIX}{ip}")
