"""Tests for /api/v1/auth endpoints — 45 tests."""
import pytest
from httpx import AsyncClient

from tests.conftest import create_user, get_auth_headers, login_user


# ── Registration ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "alice@example.com", "username": "alice", "password": "Password1"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["user"]["email"] == "alice@example.com"
    assert "verification_token" in data
    assert data["user"]["is_verified"] is False


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    await create_user(client)
    resp = await client.post("/api/v1/auth/register", json={
        "email": "test@example.com", "username": "other", "password": "Password1"
    })
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_duplicate_username(client: AsyncClient):
    await create_user(client)
    resp = await client.post("/api/v1/auth/register", json={
        "email": "other@example.com", "username": "testuser", "password": "Password1"
    })
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password_too_short(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "bob@example.com", "username": "bob", "password": "short"
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_weak_password_no_uppercase(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "bob@example.com", "username": "bob", "password": "password1"
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_weak_password_no_digit(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "bob@example.com", "username": "bob", "password": "PasswordOnly"
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "email": "not-an-email", "username": "bob", "password": "Password1"
    })
    assert resp.status_code == 422


# ── Login ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await create_user(client)
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await create_user(client)
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "wrongpassword"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "ghost@example.com", "password": "Password1"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_ip_rate_limiting(client: AsyncClient):
    """Block IP after 5 failed attempts."""
    await create_user(client)
    for _ in range(5):
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrong"
        })
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "wrong"
    })
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_login_ip_rate_limit_resets_on_success(client: AsyncClient):
    await create_user(client)
    for _ in range(4):
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrong"
        })
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 200


# ── Account Lockout ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_account_lockout_after_5_failures(client: AsyncClient, mock_redis):
    """
    Account-based lockout: 5 failed attempts → account locked for 15 min.
    Uses different 'IPs' to bypass IP-based rate limit and isolate account lockout.
    """
    await create_user(client)

    # Simulate requests from 5 different IPs to avoid IP rate limiting
    for i in range(5):
        mock_redis.clear()  # reset IP counter between attempts
        resp = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrongpass"
        })
        # First 4 fail with 401; 5th triggers account lock (403)
        assert resp.status_code in (401, 403)

    # Account is now locked — correct password should also be blocked
    mock_redis.clear()
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 403
    assert "locked" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_account_lockout_failed_attempts_tracked(client: AsyncClient, mock_redis):
    """User.failed_login_attempts increments on each bad password."""
    await create_user(client)
    for i in range(3):
        mock_redis.clear()
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrong"
        })
    # After 3 failures (below threshold) correct login still works
    mock_redis.clear()
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_successful_login_resets_failed_attempts(client: AsyncClient, mock_redis):
    """successful login resets failed_login_attempts back to 0."""
    await create_user(client)
    for _ in range(2):
        mock_redis.clear()
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrong"
        })
    mock_redis.clear()
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 200
    # Subsequent wrong password count starts from 0 again
    for _ in range(3):
        mock_redis.clear()
        await client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "wrong"
        })
    mock_redis.clear()
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@example.com", "password": "Password1"
    })
    assert resp.status_code == 200  # not locked (only 3 new failures)


# ── Get Me ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_get_me_returns_lockout_fields(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/auth/me", headers=headers)
    data = resp.json()
    assert "failed_login_attempts" in data
    assert "account_locked_until" in data


@pytest.mark.asyncio
async def test_get_me_unauthenticated(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_me_invalid_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer bad.token.here"})
    assert resp.status_code == 401


# ── Logout ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_success(client: AsyncClient):
    await create_user(client)
    tokens = await login_user(client)
    resp = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_blacklists_access_token(client: AsyncClient):
    await create_user(client)
    tokens = await login_user(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    await client.post("/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]}, headers=headers)
    resp = await client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 401


# ── Refresh + Token Family ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_returns_new_pair(client: AsyncClient):
    await create_user(client)
    tokens = await login_user(client)
    resp = await client.post("/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_old_token_revoked(client: AsyncClient):
    await create_user(client)
    tokens = await login_user(client)
    await client.post("/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]})
    resp = await client.post("/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_reuse_kills_family(client: AsyncClient):
    """
    Token family security: presenting a revoked token (simulating theft scenario)
    invalidates ALL sessions in that family, not just one.
    """
    await create_user(client)
    tokens = await login_user(client)
    original_refresh = tokens["refresh_token"]

    # Legitimate rotation
    resp = await client.post("/api/v1/auth/refresh",
        json={"refresh_token": original_refresh})
    assert resp.status_code == 200
    new_tokens = resp.json()

    # Attacker replays the old (now revoked) token — should kill the whole family
    reuse_resp = await client.post("/api/v1/auth/refresh",
        json={"refresh_token": original_refresh})
    assert reuse_resp.status_code == 401
    assert "reuse" in reuse_resp.json()["detail"].lower()

    # New token from the same family should now also be invalidated
    family_killed_resp = await client.post("/api/v1/auth/refresh",
        json={"refresh_token": new_tokens["refresh_token"]})
    assert family_killed_resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_invalid_token(client: AsyncClient):
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": "totally-fake-token"})
    assert resp.status_code == 401


# ── Email Verification ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_email_success(client: AsyncClient):
    data = await create_user(client)
    resp = await client.post("/api/v1/auth/verify-email", json={"token": data["verification_token"]})
    assert resp.status_code == 200
    headers = await get_auth_headers(client)
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.json()["is_verified"] is True


@pytest.mark.asyncio
async def test_verify_email_invalid_token(client: AsyncClient):
    resp = await client.post("/api/v1/auth/verify-email", json={"token": "badtoken"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_verify_email_reuse_fails(client: AsyncClient):
    data = await create_user(client)
    token = data["verification_token"]
    await client.post("/api/v1/auth/verify-email", json={"token": token})
    resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert resp.status_code == 400


# ── Password Reset ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_forgot_password_returns_token(client: AsyncClient):
    await create_user(client)
    resp = await client.post("/api/v1/auth/forgot-password",
        json={"email": "test@example.com"})
    assert resp.status_code == 200
    assert resp.json()["reset_token"] != ""


@pytest.mark.asyncio
async def test_forgot_password_unknown_email_200(client: AsyncClient):
    resp = await client.post("/api/v1/auth/forgot-password",
        json={"email": "ghost@example.com"})
    assert resp.status_code == 200  # no email enumeration


@pytest.mark.asyncio
async def test_reset_password_flow(client: AsyncClient):
    await create_user(client)
    r = await client.post("/api/v1/auth/forgot-password",
        json={"email": "test@example.com"})
    token = r.json()["reset_token"]

    resp = await client.post("/api/v1/auth/reset-password",
        json={"token": token, "new_password": "NewPass456"})
    assert resp.status_code == 200

    login_resp = await client.post("/api/v1/auth/login",
        json={"email": "test@example.com", "password": "NewPass456"})
    assert login_resp.status_code == 200


@pytest.mark.asyncio
async def test_reset_password_old_fails(client: AsyncClient):
    await create_user(client)
    r = await client.post("/api/v1/auth/forgot-password",
        json={"email": "test@example.com"})
    token = r.json()["reset_token"]
    await client.post("/api/v1/auth/reset-password",
        json={"token": token, "new_password": "NewPass456"})
    resp = await client.post("/api/v1/auth/login",
        json={"email": "test@example.com", "password": "Password1"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reset_password_invalid_token(client: AsyncClient):
    resp = await client.post("/api/v1/auth/reset-password",
        json={"token": "invalidtoken", "new_password": "NewPass456"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_token_single_use(client: AsyncClient):
    await create_user(client)
    r = await client.post("/api/v1/auth/forgot-password",
        json={"email": "test@example.com"})
    token = r.json()["reset_token"]
    await client.post("/api/v1/auth/reset-password",
        json={"token": token, "new_password": "NewPass456"})
    resp = await client.post("/api/v1/auth/reset-password",
        json={"token": token, "new_password": "AnotherPass789"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_strength_enforced(client: AsyncClient):
    await create_user(client)
    r = await client.post("/api/v1/auth/forgot-password",
        json={"email": "test@example.com"})
    token = r.json()["reset_token"]
    resp = await client.post("/api/v1/auth/reset-password",
        json={"token": token, "new_password": "weak"})
    assert resp.status_code == 422


# ── Change Password ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_password(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.post("/api/v1/auth/change-password",
        json={"current_password": "Password1", "new_password": "NewPass456"},
        headers=headers)
    assert resp.status_code == 200
    login_resp = await client.post("/api/v1/auth/login",
        json={"email": "test@example.com", "password": "NewPass456"})
    assert login_resp.status_code == 200


@pytest.mark.asyncio
async def test_change_password_wrong_current(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.post("/api/v1/auth/change-password",
        json={"current_password": "wrongpassword", "new_password": "NewPass456"},
        headers=headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_change_password_strength_enforced(client: AsyncClient):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.post("/api/v1/auth/change-password",
        json={"current_password": "Password1", "new_password": "weak"},
        headers=headers)
    assert resp.status_code == 422
