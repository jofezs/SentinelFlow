"""FastAPI dependencies: settings, DB sessions, and authentication."""

import secrets
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from sentinelflow_gateway.config import Settings
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import ApiKey, Project
from sentinelflow_gateway.security import is_well_formed, lookup_prefix, verify_key

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_admin_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_database(request: Request) -> Database:
    database: Database = request.app.state.database
    return database


async def get_session(
    database: Annotated[Database, Depends(get_database)],
) -> AsyncIterator[AsyncSession]:
    async with database.session() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def require_project(
    session: SessionDep,
    key: Annotated[str | None, Security(_api_key_header)],
) -> Project:
    """Authenticate an X-API-Key header and return the owning project."""
    if key is None or not is_well_formed(key):
        raise _UNAUTHORIZED
    api_key = await session.scalar(
        select(ApiKey)
        .where(ApiKey.prefix == lookup_prefix(key), ApiKey.revoked_at.is_(None))
        .options(joinedload(ApiKey.project))
    )
    if api_key is None or not verify_key(key, api_key.key_hash):
        raise _UNAUTHORIZED
    return api_key.project


def require_admin(
    settings: Annotated[Settings, Depends(get_settings)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_admin_bearer)],
) -> None:
    expected = settings.admin_token.get_secret_value()
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode(), expected.encode()
    ):
        raise _UNAUTHORIZED


ProjectDep = Annotated[Project, Depends(require_project)]
