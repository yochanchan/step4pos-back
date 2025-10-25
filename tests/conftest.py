import importlib
import os
from pathlib import Path
from typing import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure deterministic environment for tests before importing application modules.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./tests/test.db")
os.environ.setdefault("JWT_SECRET", "test-secret-key")
os.environ.setdefault("ACCESS_TOKEN_TTL_MIN", "15")
os.environ.setdefault("REFRESH_TOKEN_TTL_DAY", "14")
os.environ.setdefault("REFRESH_COOKIE_SECURE", "false")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000")
os.environ.setdefault("OIDC_LINE_CLIENT_ID", "line-client-id")
os.environ.setdefault("OIDC_LINE_CLIENT_SECRET", "line-client-secret")
os.environ.setdefault("OIDC_LINE_REDIRECT_URI", "http://localhost:3000/auth/line/callback")

# Clear cached settings so they reflect the overrides above.
import app.core.config as config_module

config_module.get_settings.cache_clear()
importlib.reload(config_module)

# Reinitialize the database session module with the updated configuration.
session_module = importlib.import_module("app.db.session")
importlib.reload(session_module)

from app.db.base import Base
from app.db.session import AsyncSessionLocal, engine
from app.main import create_app


@pytest_asyncio.fixture(scope="session")
async def prepare_database() -> AsyncIterator[None]:
    """Create all tables once for the test session."""
    Path("tests").mkdir(exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True)
async def reset_database(prepare_database) -> AsyncIterator[None]:
    """Ensure each test starts with a clean schema."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


@pytest_asyncio.fixture
async def db_session():
    async with AsyncSessionLocal() as session:
        yield session
