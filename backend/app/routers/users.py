import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.database import get_db
from app.dependencies import get_current_active_user, get_token_data
from app.models.user import User
from app.redis_client import get_redis
from app.schemas.auth import MessageResponse, SessionResponse
from app.services import session_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/sessions", response_model=List[SessionResponse])
async def list_sessions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List all active sessions for the current user."""
    sessions = await session_service.get_active_sessions(current_user.id, db)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def revoke_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Revoke a specific session (logout from one device)."""
    revoked = await session_service.revoke_session(
        session_id=session_id,
        user_id=current_user.id,
        db=db,
        redis=redis,
    )
    if not revoked:
        raise HTTPException(status_code=404, detail="Session not found")

    return MessageResponse(message="Session revoked")


@router.delete("/sessions", response_model=MessageResponse)
async def revoke_all_sessions(
    token_data=Depends(get_token_data),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Revoke all sessions except the current one (logout everywhere else)."""
    count = await session_service.revoke_all_sessions(
        user_id=current_user.id,
        db=db,
        redis=redis,
        exclude_session_id=token_data.session_id,
    )
    return MessageResponse(message=f"Revoked {count} session(s)")


@router.delete("/sessions/all/force", response_model=MessageResponse)
async def revoke_all_sessions_including_current(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Revoke ALL sessions including the current one (full logout everywhere)."""
    count = await session_service.revoke_all_sessions(
        user_id=current_user.id,
        db=db,
        redis=redis,
    )
    return MessageResponse(message=f"All {count} session(s) revoked")
