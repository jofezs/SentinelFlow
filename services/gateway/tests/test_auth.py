from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import update

from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import ApiKey
from sentinelflow_gateway.security import generate_api_key, hash_key, verify_key

from .conftest import ADMIN_HEADERS, create_project


class TestAdminAuth:
    async def test_create_project_requires_admin_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/v1/projects", json={"name": "acme"})
        assert resp.status_code == 401

    async def test_wrong_admin_token_rejected(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/v1/projects",
            json={"name": "acme"},
            headers={"Authorization": "Bearer wrong-token-wrong-token"},
        )
        assert resp.status_code == 401

    async def test_api_key_is_not_an_admin_credential(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        resp = await client.post("/v1/projects", json={"name": "acme"}, headers=api_headers)
        assert resp.status_code == 401


class TestProjects:
    async def test_create_project_returns_key_once(self, client: httpx.AsyncClient) -> None:
        project = await create_project(client, "acme")
        assert project["name"] == "acme"
        assert project["api_key"].startswith("sf_")

        me = await client.get("/v1/projects/me", headers={"X-API-Key": project["api_key"]})
        assert me.status_code == 200
        assert me.json()["id"] == project["id"]
        assert "api_key" not in me.json()

    async def test_duplicate_project_name_conflicts(self, client: httpx.AsyncClient) -> None:
        await create_project(client, "acme")
        resp = await client.post("/v1/projects", json={"name": "acme"}, headers=ADMIN_HEADERS)
        assert resp.status_code == 409

    @pytest.mark.parametrize("name", ["", "A", "Has Spaces", "-leading-dash", "x" * 64])
    async def test_invalid_project_names_rejected(
        self, client: httpx.AsyncClient, name: str
    ) -> None:
        resp = await client.post("/v1/projects", json={"name": name}, headers=ADMIN_HEADERS)
        assert resp.status_code == 422


class TestApiKeyAuth:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"X-API-Key": ""},
            {"X-API-Key": "not-a-sentinelflow-key"},
            {"X-API-Key": "sf_" + "A" * 43},  # well-formed but unknown
        ],
    )
    async def test_invalid_keys_rejected(
        self, client: httpx.AsyncClient, headers: dict[str, str]
    ) -> None:
        resp = await client.get("/v1/scans", headers=headers)
        assert resp.status_code == 401

    async def test_tampered_key_with_valid_prefix_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        key = api_headers["X-API-Key"]
        tampered = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
        resp = await client.get("/v1/scans", headers={"X-API-Key": tampered})
        assert resp.status_code == 401

    async def test_revoked_key_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        assert (await client.get("/v1/scans", headers=api_headers)).status_code == 200
        async with database.session() as session:
            await session.execute(update(ApiKey).values(revoked_at=datetime.now(UTC)))
            await session.commit()
        assert (await client.get("/v1/scans", headers=api_headers)).status_code == 401


def test_generated_keys_are_unique_and_verifiable() -> None:
    a, b = generate_api_key(), generate_api_key()
    assert a.plaintext != b.plaintext
    assert len(a.prefix) == 12
    assert a.key_hash == hash_key(a.plaintext)
    assert verify_key(a.plaintext, a.key_hash)
    assert not verify_key(b.plaintext, a.key_hash)
