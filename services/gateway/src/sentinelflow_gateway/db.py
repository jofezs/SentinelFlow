from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# Deterministic constraint names keep Alembic migrations stable across databases.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Database:
    def __init__(self, url: str, **engine_kwargs: Any) -> None:
        if not url.startswith("sqlite"):
            engine_kwargs.setdefault("pool_pre_ping", True)
        self.engine: AsyncEngine = create_async_engine(url, **engine_kwargs)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> AsyncSession:
        return self.sessionmaker()

    async def dispose(self) -> None:
        await self.engine.dispose()
