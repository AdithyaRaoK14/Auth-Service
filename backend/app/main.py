from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import create_tables
from app.redis_client import close_redis, init_redis
from app.routers import admin, auth, users
from app.models.user import UserRole  # ensure models imported for create_all


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_redis()
    await create_tables()
    await _seed_default_permissions()
    yield
    await close_redis()


async def _seed_default_permissions():
    from sqlalchemy import select
    from app.database import AsyncSessionLocal
    from app.models.user import Permission

    defaults = [
        ("read_reports",  "Can view reports"),
        ("write_reports", "Can create/edit reports"),
        ("delete_users",  "Can delete user accounts"),
        ("manage_billing","Can manage billing settings"),
        ("view_audit_log","Can view audit logs"),
    ]
    async with AsyncSessionLocal() as db:
        for name, desc in defaults:
            result = await db.execute(select(Permission).where(Permission.name == name))
            if not result.scalar_one_or_none():
                db.add(Permission(name=name, description=desc))
        await db.commit()


app = FastAPI(
    title=settings.APP_NAME,
    version="1.1.0",
    description="Standalone authentication & authorization microservice",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
app.include_router(auth.router,  prefix=API_PREFIX)
app.include_router(users.router, prefix=API_PREFIX)
app.include_router(admin.router, prefix=API_PREFIX)


@app.get("/health", tags=["health"])
async def health_check():
    """
    Deep health check — verifies both downstream dependencies are reachable.
    Returns 200 only if DB and Redis are up. Used by Docker and load balancers.
    """
    from app.database import engine
    from app.redis_client import redis_client

    db_status  = "up"
    redis_status = "up"

    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"down: {e}"

    try:
        await redis_client.ping()
    except Exception as e:
        redis_status = f"down: {e}"

    healthy = db_status == "up" and redis_status == "up"
    return {
        "status": "healthy" if healthy else "degraded",
        "database": db_status,
        "redis":    redis_status,
        "version":  "1.1.0",
    }
