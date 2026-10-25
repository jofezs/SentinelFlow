import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy.pool import StaticPool

from sentinelflow_gateway import models  # noqa: F401
from sentinelflow_gateway.config import Settings
from sentinelflow_gateway.db import Base, Database
from sentinelflow_gateway.main import create_app
from sentinelflow_gateway.publisher import AnyEvent

ADMIN_TOKEN = "test-admin-token-not-secret"
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# Defaults to in-memory SQLite; CI sets this to a real Postgres service.
TEST_DATABASE_URL = os.environ.get("SENTINELFLOW_TEST_DATABASE_URL", "sqlite+aiosqlite://")


@dataclass
class RecordingPublisher:
    published: list[tuple[str, AnyEvent]] = field(default_factory=list)

    async def publish(self, subject: str, event: AnyEvent) -> None:
        self.published.append((subject, event))

    async def close(self) -> None:
        return None


@pytest.fixture
def publisher() -> RecordingPublisher:
    return RecordingPublisher()


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    kwargs = {"poolclass": StaticPool} if TEST_DATABASE_URL.startswith("sqlite") else {}
    db = Database(TEST_DATABASE_URL, **kwargs)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


@pytest.fixture
def app(database: Database, publisher: RecordingPublisher) -> FastAPI:
    settings = Settings(database_url=TEST_DATABASE_URL, admin_token=SecretStr(ADMIN_TOKEN))
    return create_app(settings=settings, database=database, publisher=publisher)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def create_project(client: httpx.AsyncClient, name: str) -> dict[str, str]:
    resp = await client.post("/v1/projects", json={"name": name}, headers=ADMIN_HEADERS)
    assert resp.status_code == 201, resp.text
    body: dict[str, str] = resp.json()
    return body


@pytest.fixture
async def api_headers(client: httpx.AsyncClient) -> dict[str, str]:
    project = await create_project(client, "default-project")
    return {"X-API-Key": project["api_key"]}
