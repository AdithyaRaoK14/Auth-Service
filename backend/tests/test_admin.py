"""Tests for /api/v1/admin endpoints — 28 tests."""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import create_user, get_auth_headers, login_user, make_admin


# ── RBAC Enforcement ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_endpoint_blocks_regular_user(client):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/admin/users", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_endpoint_blocks_unauthenticated(client):
    resp = await client.get("/api/v1/admin/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_blocks_manager(client, db_session):
    await create_user(client, email="mgr@example.com", username="manager")
    from sqlalchemy import update
    from app.models.user import User, UserRole
    await db_session.execute(
        update(User).where(User.email == "mgr@example.com").values(role=UserRole.MANAGER)
    )
    await db_session.commit()
    headers = await get_auth_headers(client, "mgr@example.com")
    resp = await client.get("/api/v1/admin/users", headers=headers)
    assert resp.status_code == 403


# ── Pagination ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_users_pagination_structure(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    for i in range(5):
        await create_user(client, email=f"user{i}@example.com", username=f"user{i}")

    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.get("/api/v1/admin/users?page=1&limit=3", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "pages" in data
    assert "limit" in data
    assert data["limit"] == 3
    assert len(data["items"]) <= 3


@pytest.mark.asyncio
async def test_list_users_page_2(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    for i in range(4):
        await create_user(client, email=f"p{i}@example.com", username=f"puser{i}")

    headers = await get_auth_headers(client, "admin@example.com")
    r1 = await client.get("/api/v1/admin/users?page=1&limit=2", headers=headers)
    r2 = await client.get("/api/v1/admin/users?page=2&limit=2", headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    ids_p1 = {u["id"] for u in r1.json()["items"]}
    ids_p2 = {u["id"] for u in r2.json()["items"]}
    assert ids_p1.isdisjoint(ids_p2)


@pytest.mark.asyncio
async def test_list_users_search(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    await create_user(client, email="alice@example.com", username="alice")
    await create_user(client, email="bob@example.com", username="bob")

    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.get("/api/v1/admin/users?search=alice", headers=headers)
    assert resp.status_code == 200
    emails = [u["email"] for u in resp.json()["items"]]
    assert "alice@example.com" in emails
    assert "bob@example.com" not in emails


@pytest.mark.asyncio
async def test_list_users_role_filter(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    await create_user(client, email="regular@example.com", username="regular")

    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.get("/api/v1/admin/users?role=admin", headers=headers)
    assert resp.status_code == 200
    assert all(u["role"] == "admin" for u in resp.json()["items"])


# ── User Management ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_get_user(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")

    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.get(f"/api/v1/admin/users/{data['user']['id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == "target@example.com"
    assert "permissions" in resp.json()


@pytest.mark.asyncio
async def test_admin_update_role(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    user_id = data["user"]["id"]

    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.put(f"/api/v1/admin/users/{user_id}/role",
        json={"role": "manager"}, headers=headers)
    assert resp.status_code == 200

    get_resp = await client.get(f"/api/v1/admin/users/{user_id}", headers=headers)
    assert get_resp.json()["role"] == "manager"


@pytest.mark.asyncio
async def test_admin_cannot_change_own_role(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    from sqlalchemy import select
    from app.models.user import User
    result = await db_session.execute(select(User).where(User.email == "admin@example.com"))
    admin = result.scalar_one()
    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.put(f"/api/v1/admin/users/{admin.id}/role",
        json={"role": "user"}, headers=headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_admin_delete_user(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="victim@example.com", username="victim")
    user_id = data["user"]["id"]
    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.delete(f"/api/v1/admin/users/{user_id}", headers=headers)
    assert resp.status_code == 200
    assert await client.get(f"/api/v1/admin/users/{user_id}", headers=headers)


@pytest.mark.asyncio
async def test_invalid_role_update(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.put(f"/api/v1/admin/users/{data['user']['id']}/role",
        json={"role": "superuser"}, headers=headers)
    assert resp.status_code == 422


# ── Permissions ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_permissions(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    headers = await get_auth_headers(client, "admin@example.com")
    resp = await client.get("/api/v1/admin/permissions", headers=headers)
    assert resp.status_code == 200
    assert "read_reports" in [p["name"] for p in resp.json()]


@pytest.mark.asyncio
async def test_grant_and_revoke_permission(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    user_id = data["user"]["id"]
    headers = await get_auth_headers(client, "admin@example.com")

    assert (await client.post(f"/api/v1/admin/users/{user_id}/permissions",
        json={"permission": "read_reports"}, headers=headers)).status_code == 200
    assert "read_reports" in (await client.get(f"/api/v1/admin/users/{user_id}", headers=headers)).json()["permissions"]
    assert (await client.delete(f"/api/v1/admin/users/{user_id}/permissions/read_reports",
        headers=headers)).status_code == 200
    assert "read_reports" not in (await client.get(f"/api/v1/admin/users/{user_id}", headers=headers)).json()["permissions"]


@pytest.mark.asyncio
async def test_grant_duplicate_permission(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    user_id = data["user"]["id"]
    headers = await get_auth_headers(client, "admin@example.com")
    await client.post(f"/api/v1/admin/users/{user_id}/permissions",
        json={"permission": "read_reports"}, headers=headers)
    resp = await client.post(f"/api/v1/admin/users/{user_id}/permissions",
        json={"permission": "read_reports"}, headers=headers)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_permission_protected_denied(client):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/admin/reports", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_permission_protected_granted(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="reporter@example.com", username="reporter")
    admin_headers = await get_auth_headers(client, "admin@example.com")
    await client.post(f"/api/v1/admin/users/{data['user']['id']}/permissions",
        json={"permission": "read_reports"}, headers=admin_headers)
    reporter_headers = await get_auth_headers(client, "reporter@example.com")
    assert (await client.get("/api/v1/admin/reports", headers=reporter_headers)).status_code == 200


@pytest.mark.asyncio
async def test_admin_bypasses_permission_check(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    headers = await get_auth_headers(client, "admin@example.com")
    assert (await client.get("/api/v1/admin/reports", headers=headers)).status_code == 200


# ── Audit Logs ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_log_created_on_register(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    headers = await get_auth_headers(client, "admin@example.com")

    resp = await client.get("/api/v1/admin/audit-logs", headers=headers)
    assert resp.status_code == 200
    actions = [item["action"] for item in resp.json()["items"]]
    assert "USER_REGISTERED" in actions


@pytest.mark.asyncio
async def test_audit_log_created_on_login(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    await login_user(client, "admin@example.com")
    headers = await get_auth_headers(client, "admin@example.com")

    resp = await client.get("/api/v1/admin/audit-logs?action=USER_LOGIN", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_audit_log_on_role_change(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    headers = await get_auth_headers(client, "admin@example.com")
    await client.put(f"/api/v1/admin/users/{data['user']['id']}/role",
        json={"role": "manager"}, headers=headers)

    resp = await client.get("/api/v1/admin/audit-logs?action=ADMIN_ROLE_CHANGED", headers=headers)
    assert resp.status_code == 200
    log = resp.json()["items"][0]
    assert log["metadata_"]["from"] == "user"
    assert log["metadata_"]["to"] == "manager"


@pytest.mark.asyncio
async def test_audit_log_on_permission_grant(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    data = await create_user(client, email="target@example.com", username="target")
    headers = await get_auth_headers(client, "admin@example.com")
    await client.post(f"/api/v1/admin/users/{data['user']['id']}/permissions",
        json={"permission": "read_reports"}, headers=headers)

    resp = await client.get("/api/v1/admin/audit-logs?action=ADMIN_PERMISSION_GRANTED", headers=headers)
    assert resp.json()["items"][0]["metadata_"]["permission"] == "read_reports"


@pytest.mark.asyncio
async def test_audit_log_pagination(client, db_session):
    await create_user(client, email="admin@example.com", username="admin")
    await make_admin(db_session, "admin@example.com")
    # Generate several log entries via logins
    for _ in range(3):
        await login_user(client, "admin@example.com")
    headers = await get_auth_headers(client, "admin@example.com")

    resp = await client.get("/api/v1/admin/audit-logs?page=1&limit=2", headers=headers)
    data = resp.json()
    assert len(data["items"]) <= 2
    assert data["total"] >= 3
    assert data["pages"] >= 2


@pytest.mark.asyncio
async def test_audit_log_blocked_for_non_admin(client):
    await create_user(client)
    headers = await get_auth_headers(client)
    resp = await client.get("/api/v1/admin/audit-logs", headers=headers)
    assert resp.status_code == 403
