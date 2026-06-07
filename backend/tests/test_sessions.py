"""Tests for /api/v1/users/sessions endpoints."""
import pytest
from httpx import AsyncClient

from tests.conftest import create_user, get_auth_headers, login_user


@pytest.mark.asyncio
async def test_list_sessions(client: AsyncClient):
    await create_user(client)
    await login_user(client)  # creates a session
    headers = await get_auth_headers(client)

    resp = await client.get("/api/v1/users/sessions", headers=headers)
    assert resp.status_code == 200
    sessions = resp.json()
    assert isinstance(sessions, list)
    assert len(sessions) >= 1


@pytest.mark.asyncio
async def test_list_sessions_has_device_info(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)

    resp = await client.get("/api/v1/users/sessions", headers=headers)
    assert resp.status_code == 200
    session = resp.json()[0]
    assert "id" in session
    assert "device_info" in session
    assert "ip_address" in session
    assert "created_at" in session
    assert "last_active" in session
    assert "is_active" in session


@pytest.mark.asyncio
async def test_multiple_sessions(client: AsyncClient):
    await create_user(client)
    # Create 3 sessions
    for _ in range(3):
        await login_user(client)

    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/users/sessions", headers=headers)
    assert resp.status_code == 200
    # Should have at least 3 sessions (3 logins above + 1 for get_auth_headers)
    assert len(resp.json()) >= 3


@pytest.mark.asyncio
async def test_revoke_specific_session(client: AsyncClient):
    await create_user(client)
    await login_user(client)
    headers = await get_auth_headers(client)

    sessions_resp = await client.get("/api/v1/users/sessions", headers=headers)
    sessions = sessions_resp.json()
    assert len(sessions) >= 2

    # Revoke the first session (not the current one)
    target_session_id = sessions[1]["id"]
    resp = await client.delete(
        f"/api/v1/users/sessions/{target_session_id}", headers=headers
    )
    assert resp.status_code == 200

    # Session count should decrease
    sessions_resp2 = await client.get("/api/v1/users/sessions", headers=headers)
    assert len(sessions_resp2.json()) == len(sessions) - 1


@pytest.mark.asyncio
async def test_revoke_nonexistent_session(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    import uuid
    fake_id = str(uuid.uuid4())
    resp = await client.delete(f"/api/v1/users/sessions/{fake_id}", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_revoke_all_sessions_excludes_current(client: AsyncClient):
    await create_user(client)
    # Create extra sessions
    for _ in range(3):
        await login_user(client)

    headers = await get_auth_headers(client)
    resp = await client.delete("/api/v1/users/sessions", headers=headers)
    assert resp.status_code == 200
    assert "Revoked" in resp.json()["message"]

    # Current session should still work
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200


@pytest.mark.asyncio
async def test_revoke_all_sessions_including_current(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)

    resp = await client.delete("/api/v1/users/sessions/all/force", headers=headers)
    assert resp.status_code == 200

    sessions_resp = await client.get("/api/v1/users/sessions", headers=headers)
    # Access token still works (it's not blacklisted by this endpoint)
    assert sessions_resp.status_code == 200
    # But no active sessions remain
    assert len(sessions_resp.json()) == 0


@pytest.mark.asyncio
async def test_sessions_unauthenticated(client: AsyncClient):
    resp = await client.get("/api/v1/users/sessions")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_cannot_revoke_other_users_session(client: AsyncClient, db_session):
    # Create two users
    await create_user(client, email="user1@example.com", username="user1")
    await create_user(client, email="user2@example.com", username="user2")

    # Login as user2 to get a session ID
    tokens2 = await login_user(client, "user2@example.com")
    headers2 = {"Authorization": f"Bearer {tokens2['access_token']}"}
    sessions2_resp = await client.get("/api/v1/users/sessions", headers=headers2)
    session2_id = sessions2_resp.json()[0]["id"]

    # Try to revoke user2's session as user1
    headers1 = await get_auth_headers(client, "user1@example.com")
    resp = await client.delete(
        f"/api/v1/users/sessions/{session2_id}", headers=headers1
    )
    assert resp.status_code == 404  # not found for this user
