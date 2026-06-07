"""
Test configuration.
Uses SQLite (aiosqlite) for DB and a mock Redis dict for speed.
"""
import asyncio
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.main import app
from app.redis_client import get_redis

# ─── Test Database (SQLite) ───────────────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///./test.db"

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="session")
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed default permissions into test DB
    async with TestSessionLocal() as session:
        from app.models.user import Permission
        from sqlalchemy import select
        default_permissions = [
            ("read_reports", "Can view reports"),
            ("write_reports", "Can create/edit reports"),
            ("delete_users", "Can delete user accounts"),
            ("manage_billing", "Can manage billing settings"),
            ("view_audit_log", "Can view audit logs"),
        ]
        for name, desc in default_permissions:
            result = await session.execute(select(Permission).where(Permission.name == name))
            if not result.scalar_one_or_none():
                session.add(Permission(name=name, description=desc))
        await session.commit()
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture
async def db_session(setup_db) -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()
        # Clean all tables between tests except seeded lookups
        from sqlalchemy import text
        skip_tables = {"permissions"}
        for table in reversed(Base.metadata.sorted_tables):
            if table.name not in skip_tables:
                await session.execute(text(f"DELETE FROM {table.name}"))
        await session.commit()


# ─── Mock Redis ───────────────────────────────────────────────────────────────

class MockRedis:
    """In-memory Redis mock for testing."""

    def __init__(self):
        self._store: dict = {}
        self._ttls: dict = {}

    async def get(self, key: str):
        return self._store.get(key)

    async def set(self, key: str, value, ex: int = None):
        self._store[key] = value
        if ex:
            self._ttls[key] = ex

    async def setex(self, key: str, seconds: int, value):
        self._store[key] = value
        self._ttls[key] = seconds

    async def incr(self, key: str) -> int:
        val = int(self._store.get(key, 0)) + 1
        self._store[key] = str(val)
        return val

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -2)

    async def delete(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if k in self._store:
                del self._store[k]
                count += 1
        return count

    async def sadd(self, key: str, *values) -> int:
        if key not in self._store:
            self._store[key] = set()
        added = 0
        for v in values:
            if v not in self._store[key]:
                self._store[key].add(v)
                added += 1
        return added

    async def srem(self, key: str, *values) -> int:
        if key not in self._store:
            return 0
        removed = 0
        for v in values:
            try:
                self._store[key].discard(v)
                removed += 1
            except Exception:
                pass
        return removed

    async def smembers(self, key: str):
        return self._store.get(key, set())

    async def aclose(self):
        pass

    def clear(self):
        self._store.clear()
        self._ttls.clear()


@pytest.fixture
def mock_redis():
    r = MockRedis()
    yield r
    r.clear()


# ─── Test Client ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(db_session, mock_redis) -> AsyncGenerator[AsyncClient, None]:
    """AsyncClient with overridden DB and Redis dependencies."""

    async def override_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    async def override_redis():
        return mock_redis

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = override_redis

    # Disable lifespan (avoids real postgres/redis connection during tests)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=True),
        base_url="http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()


# ─── Helper Factories ─────────────────────────────────────────────────────────

async def create_user(
    client: AsyncClient,
    email: str = "test@example.com",
    username: str = "testuser",
    password: str = "Password1",
) -> dict:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "username": username, "password": password},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def verify_user(client: AsyncClient, token: str) -> None:
    resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert resp.status_code == 200, resp.text


async def login_user(
    client: AsyncClient,
    email: str = "test@example.com",
    password: str = "Password1",
) -> dict:
    resp = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def get_auth_headers(client: AsyncClient, email: str = "test@example.com", password: str = "Password1") -> dict:
    tokens = await login_user(client, email, password)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def make_admin(db_session: AsyncSession, email: str) -> None:
    from sqlalchemy import update
    from app.models.user import User, UserRole
    await db_session.execute(update(User).where(User.email == email).values(role=UserRole.ADMIN))
    await db_session.commit()
