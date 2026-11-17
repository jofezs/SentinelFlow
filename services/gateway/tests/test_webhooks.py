import json
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select, update

from sentinelflow_common.events import (
    PolicyEvaluated,
    PolicyViolation,
    ScanCompleted,
    ScanStatus,
    Severity,
    TargetType,
)
from sentinelflow_common.ssrf import DestinationPolicy
from sentinelflow_gateway import webhooks
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.ingest import ResultsIngester
from sentinelflow_gateway.models import DeliveryStatus, Project, WebhookDelivery
from sentinelflow_gateway.notifier import HttpSender, Notifier

from .conftest import submit_scan

SECRET = "whsec_test-secret"


class TestSignatures:
    body = b'{"id":"1"}'

    def test_round_trip(self) -> None:
        header = webhooks.sign(SECRET, int(time.time()), self.body)
        assert webhooks.verify(SECRET, header, self.body)

    @pytest.mark.parametrize(
        ("secret", "body", "age"),
        [
            ("whsec_wrong", body, 0),  # wrong secret
            (SECRET, b'{"id":"2"}', 0),  # tampered body
            (SECRET, body, 3600),  # replayed (too old)
        ],
    )
    def test_rejections(self, secret: str, body: bytes, age: int) -> None:
        header = webhooks.sign(secret, int(time.time()) - age, self.body)
        assert not webhooks.verify(SECRET, header, body)

    @pytest.mark.parametrize("header", ["", "garbage", "t=abc,v1=00", "v1=deadbeef"])
    def test_malformed_headers(self, header: str) -> None:
        assert not webhooks.verify(SECRET, header, self.body)


class TestWebhookApi:
    async def test_configure_rotate_and_delete(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        url = "/v1/projects/me/webhook"
        assert (await client.get(url, headers=api_headers)).status_code == 404

        created = await client.put(
            url, json={"url": "https://hooks.example.com/x"}, headers=api_headers
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["secret"].startswith("whsec_")
        assert body["events"] == ["policy.failed"]

        read = (await client.get(url, headers=api_headers)).json()
        assert "secret" not in read
        assert read["secret_hint"] == body["secret"][:10] + "..."

        rotated = (
            await client.put(url, json={"url": "https://hooks.example.com/x"}, headers=api_headers)
        ).json()
        assert rotated["secret"] != body["secret"]

        assert (await client.delete(url, headers=api_headers)).status_code == 204
        assert (await client.get(url, headers=api_headers)).status_code == 404

    @pytest.mark.parametrize(
        "payload",
        [
            {"url": "ftp://example.com/hook"},
            {"url": "https://user:pass@example.com/hook"},
            {"url": "https://example.com", "events": ["scan.exploded"]},
            {"url": "https://example.com", "events": []},
        ],
    )
    async def test_invalid_config_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], payload: dict[str, Any]
    ) -> None:
        resp = await client.put("/v1/projects/me/webhook", json=payload, headers=api_headers)
        assert resp.status_code == 422

    async def test_ping_is_queued_and_listed(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        assert (
            await client.post("/v1/projects/me/webhook/test", headers=api_headers)
        ).status_code == 404
        await client.put(
            "/v1/projects/me/webhook", json={"url": "https://example.com/h"}, headers=api_headers
        )
        ping = await client.post("/v1/projects/me/webhook/test", headers=api_headers)
        assert ping.status_code == 202
        assert ping.json()["event_type"] == "ping"
        assert ping.json()["status"] == "pending"

        listed = (
            await client.get("/v1/projects/me/webhook/deliveries", headers=api_headers)
        ).json()
        assert [d["id"] for d in listed] == [ping.json()["id"]]


async def _deliveries(database: Database) -> list[WebhookDelivery]:
    async with database.session() as session:
        return list(await session.scalars(select(WebhookDelivery)))


async def _subscribe(
    client: httpx.AsyncClient, headers: dict[str, str], events: list[str] | None = None
) -> str:
    body: dict[str, Any] = {"url": "https://hooks.example.com/sf"}
    if events:
        body["events"] = events
    resp = await client.put("/v1/projects/me/webhook", json=body, headers=headers)
    secret: str = resp.json()["secret"]
    return secret


def _completed(scan: dict[str, str], status: ScanStatus = ScanStatus.SUCCEEDED) -> ScanCompleted:
    return ScanCompleted(
        scan_id=uuid.UUID(scan["id"]),
        project_id=uuid.UUID(scan["project_id"]),
        target_type=TargetType.DOCKERFILE,
        scanner="s",
        status=status,
        error=None if status == ScanStatus.SUCCEEDED else "hadolint timed out",
    )


def _decision(scan: dict[str, str], passed: bool) -> PolicyEvaluated:
    return PolicyEvaluated(
        scan_id=uuid.UUID(scan["id"]),
        project_id=uuid.UUID(scan["project_id"]),
        passed=passed,
        violations=()
        if passed
        else (PolicyViolation(policy_id="no_root_container", message="m", severity=Severity.HIGH),),
    )


class TestEnqueueOnEvents:
    async def test_policy_failure_queues_signed_payload(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        await _subscribe(client, api_headers)
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        ingester = ResultsIngester(database)
        await ingester(_completed(scan))
        await ingester(_decision(scan, passed=False))

        [delivery] = await _deliveries(database)
        payload = json.loads(delivery.payload)
        assert payload["type"] == "policy.failed"
        assert payload["id"] == str(delivery.id)
        assert payload["data"]["scan"]["id"] == scan["id"]
        assert payload["data"]["scan"]["policy_passed"] is False
        assert payload["data"]["violations"][0]["policy_id"] == "no_root_container"

    async def test_unsubscribed_events_are_not_queued(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        await _subscribe(client, api_headers)  # default: policy.failed only
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        ingester = ResultsIngester(database)
        await ingester(_completed(scan))
        await ingester(_decision(scan, passed=True))
        assert await _deliveries(database) == []

    async def test_scan_failure_event(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        await _subscribe(client, api_headers, events=["scan.failed"])
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        await ResultsIngester(database)(_completed(scan, ScanStatus.FAILED))
        [delivery] = await _deliveries(database)
        assert json.loads(delivery.payload)["data"]["error"] == "hadolint timed out"

    async def test_no_webhook_no_delivery(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        ingester = ResultsIngester(database)
        await ingester(_completed(scan))
        await ingester(_decision(scan, passed=False))
        assert await _deliveries(database) == []


@dataclass
class FakeSender:
    responses: list[int | Exception] = field(default_factory=list)
    sent: list[tuple[str, bytes, dict[str, str]]] = field(default_factory=list)

    async def send(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        self.sent.append((url, body, headers))
        result = self.responses.pop(0) if self.responses else 200
        if isinstance(result, Exception):
            raise result
        return result


class TestNotifier:
    @pytest.fixture
    async def queued(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> tuple[str, str]:
        secret = await _subscribe(client, api_headers)
        ping = await client.post("/v1/projects/me/webhook/test", headers=api_headers)
        delivery_id: str = ping.json()["id"]
        return delivery_id, secret

    async def _get(self, database: Database, delivery_id: str) -> WebhookDelivery:
        async with database.session() as session:
            delivery = await session.get(WebhookDelivery, uuid.UUID(delivery_id))
            assert delivery is not None
            return delivery

    async def _make_due(self, database: Database) -> None:
        async with database.session() as session:
            await session.execute(
                update(WebhookDelivery).values(next_attempt_at=WebhookDelivery.created_at)
            )
            await session.commit()

    async def test_successful_delivery_is_signed(
        self, database: Database, queued: tuple[str, str]
    ) -> None:
        delivery_id, secret = queued
        sender = FakeSender()
        assert await Notifier(database, sender).run_once() == 1

        url, body, headers = sender.sent[0]
        assert url == "https://hooks.example.com/sf"
        assert headers["X-SentinelFlow-Event"] == "ping"
        assert headers["X-SentinelFlow-Delivery"] == delivery_id
        assert webhooks.verify(secret, headers["X-SentinelFlow-Signature"], body)

        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.DELIVERED
        assert delivery.attempts == 1
        assert delivery.last_status_code == 200

    async def test_server_error_is_retried_with_backoff(
        self, database: Database, queued: tuple[str, str]
    ) -> None:
        delivery_id, _ = queued
        notifier = Notifier(database, FakeSender([503, 200]))
        await notifier.run_once()
        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.PENDING
        assert delivery.last_error == "HTTP 503"
        assert await notifier.run_once() == 0  # backoff: not due yet

        await self._make_due(database)
        await notifier.run_once()
        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.DELIVERED
        assert delivery.attempts == 2

    @pytest.mark.parametrize("response", [400, 404, 410])
    async def test_client_errors_fail_permanently(
        self, database: Database, queued: tuple[str, str], response: int
    ) -> None:
        delivery_id, _ = queued
        await Notifier(database, FakeSender([response])).run_once()
        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.FAILED
        assert delivery.last_status_code == response

    async def test_gives_up_after_max_attempts(
        self, database: Database, queued: tuple[str, str]
    ) -> None:
        delivery_id, _ = queued
        notifier = Notifier(
            database, FakeSender([httpx.ConnectError("refused")] * 3), max_attempts=3
        )
        for _ in range(3):
            await self._make_due(database)
            await notifier.run_once()
        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.FAILED
        assert delivery.attempts == 3
        assert delivery.last_error is not None and "ConnectError" in delivery.last_error

    async def test_claimed_delivery_is_leased(
        self, database: Database, queued: tuple[str, str]
    ) -> None:
        notifier = Notifier(database, FakeSender())
        assert len(await notifier.claim_due()) == 1
        assert await notifier.claim_due() == []  # leased: a second replica sees nothing

    async def test_removed_webhook_fails_pending_deliveries(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database,
        queued: tuple[str, str],
    ) -> None:  # fmt: skip
        delivery_id, _ = queued
        await client.delete("/v1/projects/me/webhook", headers=api_headers)
        sender = FakeSender()
        await Notifier(database, sender).run_once()
        assert sender.sent == []
        delivery = await self._get(database, delivery_id)
        assert delivery.status == DeliveryStatus.FAILED
        assert delivery.last_error == "webhook was removed"


received: list[tuple[dict[str, str], bytes]] = []


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        received.append(({k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def receiver() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    server.shutdown()


async def test_http_sender_delivers_over_the_network(receiver: str) -> None:
    sender = HttpSender(DestinationPolicy(allowed_ports=None, allow_private=True), timeout=5)
    body = b'{"hello":"world"}'
    headers = {"X-SentinelFlow-Signature": webhooks.sign(SECRET, int(time.time()), body)}
    assert await sender.send(receiver, body, headers) == 204
    await sender.close()
    seen_headers, seen_body = received[-1]
    assert seen_body == body
    assert webhooks.verify(SECRET, seen_headers["x-sentinelflow-signature"], seen_body)


async def test_notifier_blocks_internal_destinations(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    async with database.session() as session:
        await session.execute(
            update(Project).values(
                webhook_url="http://169.254.169.254/latest/meta-data/", webhook_secret=SECRET
            )
        )
        await session.commit()
    await client.post("/v1/projects/me/webhook/test", headers=api_headers)

    sender = HttpSender(DestinationPolicy(), timeout=5)
    await Notifier(database, sender).run_once()
    await sender.close()
    [delivery] = await _deliveries(database)
    assert delivery.status == DeliveryStatus.FAILED  # permanent: never retried
    assert delivery.last_error is not None and "not allowed" in delivery.last_error


def test_business_metrics_are_initialized_at_zero() -> None:
    # Present before any event, so increase()/rate() can count the very first one.
    for name, labels in [
        ("sentinelflow_policy_decisions_total", {"target_type": "image", "result": "failed"}),
        ("sentinelflow_policy_violations_total", {"policy_id": "no_secrets"}),
        ("sentinelflow_webhook_deliveries_total", {"outcome": "failed"}),
    ]:
        assert REGISTRY.get_sample_value(name, labels) is not None, name


async def test_request_metrics_use_route_templates(
    client: httpx.AsyncClient, api_headers: dict[str, str]
) -> None:
    labels = {"method": "GET", "route": "/v1/scans/{scan_id}", "status": "404"}
    before = REGISTRY.get_sample_value("sentinelflow_http_requests_total", labels) or 0
    await client.get(f"/v1/scans/{uuid.uuid4()}", headers=api_headers)
    after = REGISTRY.get_sample_value("sentinelflow_http_requests_total", labels)
    assert after == before + 1
