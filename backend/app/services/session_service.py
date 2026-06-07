import uuid
from datetime import datetime, timezone
from typing import List, Optional

import redis.asyncio as aioredis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import RefreshToken, Session
from app.services.token_service import (
    generate_refresh_token,
    refresh_token_expiry,
)

SESSION_SET_PREFIX = "sessions:user:"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Session Creation ──────────────────────────────────────────────────────────

async def create_session(
    user_id: uuid.UUID,
    device_info: Optional[str],
    ip_address: Optional[str],
    db: AsyncSession,
    redis: aioredis.Redis,
) -> tuple["Session", str]:
    """
    Create a new session + initial refresh token (new family).
    Returns (session, raw_refresh_token).
    """
    session = Session(
        user_id=user_id,
        device_info=device_info,
        ip_address=ip_address,
        is_active=True,
    )
    db.add(session)
    await db.flush()

    raw_token, token_hash = generate_refresh_token()
    # Every new login starts a fresh token_family_id
    family_id = uuid.uuid4()
    refresh_token = RefreshToken(
        user_id=user_id,
        session_id=session.id,
        token_family_id=family_id,
        token_hash=token_hash,
        expires_at=refresh_token_expiry(),
        is_revoked=False,
    )
    db.add(refresh_token)
    await _add_session_to_redis(redis, user_id, session.id)

    return session, raw_token


async def _add_session_to_redis(
    redis: aioredis.Redis, user_id: uuid.UUID, session_id: uuid.UUID
) -> None:
    key = f"{SESSION_SET_PREFIX}{user_id}"
    await redis.sadd(key, str(session_id))
    await redis.expire(key, 8 * 24 * 3600)


# ── Token Rotation with Family-Based Reuse Detection ─────────────────────────

async def rotate_refresh_token(
    old_token_hash: str,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> tuple[Optional["Session"], str, bool]:
    """
    Rotate a refresh token.
    Returns (session, new_raw_token, reuse_detected).

    Reuse detection:
      If the presented token is already revoked, it means either:
        (a) a legitimate double-submit race, or
        (b) an attacker replayed a stolen token after the real user already rotated it.
      In both cases we revoke the entire token FAMILY and all associated sessions.
      The caller should treat this as a security event and log/alert accordingly.
    """
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == old_token_hash)
    )
    rt = result.scalar_one_or_none()

    # ── Token not found at all ────────────────────────────────────────────────
    if rt is None:
        raise ValueError("Refresh token not found")

    # ── Token already revoked → possible theft, kill the whole family ─────────
    if rt.is_revoked:
        await _revoke_token_family(rt.token_family_id, rt.user_id, db, redis)
        # Return reuse flag instead of raising — caller must commit() before
        # raising HTTPException, otherwise the revocation gets rolled back.
        return None, "", True

    # ── Expired ───────────────────────────────────────────────────────────────
    now = _utcnow()
    expires_at = rt.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise ValueError("Refresh token expired")

    # ── Valid — revoke old token, issue new one in the same family ────────────
    rt.is_revoked = True

    session_result = await db.execute(
        select(Session).where(Session.id == rt.session_id, Session.is_active == True)  # noqa: E712
    )
    session = session_result.scalar_one_or_none()
    if session is None:
        raise ValueError("Session not found or revoked")

    raw_token, token_hash = generate_refresh_token()
    new_rt = RefreshToken(
        user_id=rt.user_id,
        session_id=session.id,
        token_family_id=rt.token_family_id,  # ← inherit family
        token_hash=token_hash,
        expires_at=refresh_token_expiry(),
        is_revoked=False,
    )
    db.add(new_rt)
    session.last_active = now

    return session, raw_token, False


async def _revoke_token_family(
    family_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> None:
    """
    Revoke every token in a family and every session they belong to.
    Called when token reuse is detected.
    """
    # Find all tokens in this family
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_family_id == family_id,
            RefreshToken.user_id == user_id,
        )
    )
    tokens = result.scalars().all()

    session_ids = {rt.session_id for rt in tokens}
    for rt in tokens:
        rt.is_revoked = True

    # Revoke all associated sessions
    for sid in session_ids:
        sess_result = await db.execute(
            select(Session).where(Session.id == sid)
        )
        sess = sess_result.scalar_one_or_none()
        if sess:
            sess.is_active = False
            await redis.srem(f"{SESSION_SET_PREFIX}{user_id}", str(sid))


# ── Session Revocation ────────────────────────────────────────────────────────

async def revoke_session(
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> bool:
    result = await db.execute(
        select(Session).where(
            Session.id == session_id,
            Session.user_id == user_id,
            Session.is_active == True,  # noqa: E712
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        return False

    session.is_active = False
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.session_id == session_id)
        .values(is_revoked=True)
    )
    await redis.srem(f"{SESSION_SET_PREFIX}{user_id}", str(session_id))
    return True


async def revoke_all_sessions(
    user_id: uuid.UUID,
    db: AsyncSession,
    redis: aioredis.Redis,
    exclude_session_id: Optional[uuid.UUID] = None,
) -> int:
    query = select(Session).where(
        Session.user_id == user_id,
        Session.is_active == True,  # noqa: E712
    )
    if exclude_session_id:
        query = query.where(Session.id != exclude_session_id)

    result = await db.execute(query)
    sessions = result.scalars().all()

    for s in sessions:
        s.is_active = False
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == s.id)
            .values(is_revoked=True)
        )
        await redis.srem(f"{SESSION_SET_PREFIX}{user_id}", str(s.id))

    return len(sessions)


async def revoke_session_by_refresh_hash(
    token_hash: str,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt = result.scalar_one_or_none()
    if rt:
        rt.is_revoked = True
        await revoke_session(rt.session_id, rt.user_id, db, redis)


# ── Session Queries ───────────────────────────────────────────────────────────

async def get_active_sessions(
    user_id: uuid.UUID, db: AsyncSession
) -> List[Session]:
    result = await db.execute(
        select(Session).where(
            Session.user_id == user_id,
            Session.is_active == True,  # noqa: E712
        ).order_by(Session.last_active.desc())
    )
    return result.scalars().all()
