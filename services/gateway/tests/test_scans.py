import uuid

import httpx
import pytest
from sqlalchemy import select

from sentinelflow_common.events import ScanRequested, decode_event
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import OutboxEvent

from .conftest import create_project

DIGEST = "sha256:" + "a" * 64


class TestSubmitScan:
    async def test_submit_image_scan_queues_and_writes_outbox(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        resp = await client.post(
            "/v1/scans", json={"target_type": "image", "target": "nginx:1.27"}, headers=api_headers
        )
        assert resp.status_code == 202, resp.text
        scan = resp.json()
        assert scan["status"] == "queued"
        assert scan["target"] == "nginx:1.27"
        assert scan["finding_count"] == 0

        async with database.session() as session:
            rows = (await session.scalars(select(OutboxEvent))).all()
        assert len(rows) == 1
        assert rows[0].subject == "scan.requested.image"
        assert rows[0].published_at is None
        event = decode_event(rows[0].payload)
        assert isinstance(event, ScanRequested)
        assert event.event_id == rows[0].id
        assert str(event.scan_id) == scan["id"]
        assert str(event.project_id) == scan["project_id"]

    async def test_rejected_scan_writes_no_outbox_event(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        resp = await client.post(
            "/v1/scans", json={"target_type": "image", "target": "-rf"}, headers=api_headers
        )
        assert resp.status_code == 422
        async with database.session() as session:
            assert (await session.scalars(select(OutboxEvent))).all() == []

    @pytest.mark.parametrize(
        "target",
        [
            "nginx",
            "nginx:1.27-alpine",
            "library/nginx:latest",
            "ghcr.io/jofezs/sentinelflow-gateway:0.1.0",
            "localhost:5000/team/app:dev",
            "registry:5000/app",
            "My-Registry.example.com/team/app",
            f"alpine@{DIGEST}",
        ],
    )
    async def test_valid_image_refs_accepted(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], target: str
    ) -> None:
        resp = await client.post(
            "/v1/scans", json={"target_type": "image", "target": target}, headers=api_headers
        )
        assert resp.status_code == 202, resp.text

    @pytest.mark.parametrize(
        "target",
        [
            "--config=/etc/passwd",  # CLI flag injection
            "-rf",
            "nginx; rm -rf /",  # shell metacharacters
            "nginx$(whoami)",
            "UPPER/case",  # uppercase repo (no dot/port, so not a registry)
            "-evil.com/app",
            "nginx:",
            "a" * 300,
        ],
    )
    async def test_malicious_or_invalid_image_refs_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], target: str
    ) -> None:
        resp = await client.post(
            "/v1/scans", json={"target_type": "image", "target": target}, headers=api_headers
        )
        assert resp.status_code == 422

    async def test_dockerfile_requires_from(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        ok = await client.post(
            "/v1/scans",
            json={"target_type": "dockerfile", "target": "ARG V=3\nFROM python:3.12\nUSER app\n"},
            headers=api_headers,
        )
        assert ok.status_code == 202
        bad = await client.post(
            "/v1/scans",
            json={"target_type": "dockerfile", "target": "RUN echo no base image"},
            headers=api_headers,
        )
        assert bad.status_code == 422

    async def test_oversized_dockerfile_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        huge = "FROM alpine\n" + "RUN true\n" * 10_000
        resp = await client.post(
            "/v1/scans", json={"target_type": "dockerfile", "target": huge}, headers=api_headers
        )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("https://api.example.com/v1/health", 202),
            ("http://example.com", 202),
            ("ftp://example.com/file", 422),
            ("file:///etc/passwd", 422),
            ("https://user:pass@example.com", 422),
            ("https://", 422),
            ("not a url", 422),
        ],
    )
    async def test_api_endpoint_validation(
        self,
        client: httpx.AsyncClient,
        api_headers: dict[str, str],
        target: str,
        expected: int,
    ) -> None:
        resp = await client.post(
            "/v1/scans", json={"target_type": "api_endpoint", "target": target}, headers=api_headers
        )
        assert resp.status_code == expected, resp.text

    async def test_unknown_fields_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        resp = await client.post(
            "/v1/scans",
            json={"target_type": "image", "target": "nginx", "status": "completed"},
            headers=api_headers,
        )
        assert resp.status_code == 422


class TestReadScans:
    async def _submit(self, client: httpx.AsyncClient, headers: dict[str, str], **body: str) -> str:
        resp = await client.post("/v1/scans", json=body, headers=headers)
        assert resp.status_code == 202, resp.text
        scan_id: str = resp.json()["id"]
        return scan_id

    async def test_get_scan(self, client: httpx.AsyncClient, api_headers: dict[str, str]) -> None:
        scan_id = await self._submit(client, api_headers, target_type="image", target="redis:7")
        resp = await client.get(f"/v1/scans/{scan_id}", headers=api_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["target"] == "redis:7"
        assert body["findings"] == []
        assert body["error"] is None

    async def test_unknown_scan_is_404(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        resp = await client.get(f"/v1/scans/{uuid.uuid4()}", headers=api_headers)
        assert resp.status_code == 404

    async def test_tenant_isolation(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        scan_id = await self._submit(client, api_headers, target_type="image", target="redis:7")
        other = await create_project(client, "other-tenant")
        other_headers = {"X-API-Key": other["api_key"]}

        assert (await client.get(f"/v1/scans/{scan_id}", headers=other_headers)).status_code == 404
        listing = await client.get("/v1/scans", headers=other_headers)
        assert listing.json()["total"] == 0

    async def test_list_filters_and_paginates(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        for tag in ("1", "2", "3"):
            await self._submit(client, api_headers, target_type="image", target=f"app:{tag}")
        await self._submit(
            client, api_headers, target_type="api_endpoint", target="https://example.com"
        )

        page = (await client.get("/v1/scans?limit=2", headers=api_headers)).json()
        assert page["total"] == 4
        assert len(page["items"]) == 2

        page2 = (await client.get("/v1/scans?limit=2&offset=2", headers=api_headers)).json()
        ids = {s["id"] for s in page["items"]} | {s["id"] for s in page2["items"]}
        assert len(ids) == 4

        images = (await client.get("/v1/scans?target_type=image", headers=api_headers)).json()
        assert images["total"] == 3

        queued = (await client.get("/v1/scans?status=queued", headers=api_headers)).json()
        assert queued["total"] == 4

    @pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "status=bogus"])
    async def test_invalid_query_params(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], query: str
    ) -> None:
        resp = await client.get(f"/v1/scans?{query}", headers=api_headers)
        assert resp.status_code == 422
