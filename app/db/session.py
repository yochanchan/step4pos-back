from __future__ import annotations

from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

_connect_args = {}
if (
    settings.database_ssl_ca_path
    and settings.database_url.startswith("mysql")
):
    _connect_args["ssl"] = {"ca": settings.database_ssl_ca_path}

if not settings.database_url:
    raise RuntimeError(
        "DATABASE_URL is not configured. Set DATABASE_URL or legacy DB_* variables."
    )

engine = create_async_engine(
    settings.database_url,
    echo=settings.database_echo,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args=_connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_async_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session
