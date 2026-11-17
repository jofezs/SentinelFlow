"""Webhook notifier: delivers queued webhook_deliveries with retries.

Run with: python -m sentinelflow_gateway.notifier

Claim/lease pattern: due rows are claimed with FOR UPDATE SKIP LOCKED and
leased by pushing next_attempt_at forward, then the transaction commits *before*
any HTTP call. Slow receivers therefore never hold database locks, replicas
never double-send, and if a notifier dies mid-send the lease expires and the
delivery is retried (at-least-once; receivers dedupe on the delivery id).
"""

import asyncio
import contextlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

import httpx
from sqlalchemy import select

from sentinelflow_common.bus import install_signal_handlers
from sentinelflow_common.health import Heartbeat
from sentinelflow_common.metrics import serve_metrics
from sentinelflow_common.ssrf import (
    BlockedDestination,
    DestinationPolicy,
    ProbeError,
    guarded_client,
)
from sentinelflow_common.worker import configure_logging
from sentinelflow_gateway import __version__
from sentinelflow_gateway.config import NotifierSettings
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.metrics import WEBHOOK_DELIVERIES, WEBHOOK_LATENCY
from sentinelflow_gateway.models import DeliveryStatus, Project, WebhookDelivery, utcnow
from sentinelflow_gateway.webhooks import sign

logger = logging.getLogger(__name__)

LEASE = timedelta(seconds=60)
BACKOFF_SECONDS = (10, 30, 120, 600, 1800)  # after attempt 1, 2, 3, ...
USER_AGENT = f"SentinelFlow-Webhooks/{__version__}"


def backoff(attempts: int) -> timedelta:
    return timedelta(seconds=BACKOFF_SECONDS[min(attempts, len(BACKOFF_SECONDS)) - 1])


def is_retryable(status: int) -> bool:
    """5xx, 408 and 429 are worth retrying; other non-2xx responses are permanent."""
    return status >= 500 or status in {408, 429}


class Sender(Protocol):
    async def send(self, url: str, body: bytes, headers: dict[str, str]) -> int: ...


class HttpSender:
    """POSTs through the SSRF guard; TLS verified; redirects are not followed."""

    def __init__(self, policy: DestinationPolicy, timeout: float) -> None:
        self._client = guarded_client(policy, timeout, follow_redirects=False)

    async def send(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        with WEBHOOK_LATENCY.time():
            resp = await self._client.post(url, content=body, headers=headers)
        return resp.status_code

    async def close(self) -> None:
        await self._client.aclose()


@dataclass(frozen=True)
class Claim:
    delivery_id: uuid.UUID
    event_type: str
    url: str
    secret: str
    payload: str


class Notifier:
    def __init__(
        self,
        database: Database,
        sender: Sender,
        batch_size: int = 20,
        max_attempts: int = 6,
        concurrency: int = 10,
    ) -> None:
        self._db = database
        self._sender = sender
        self._batch_size = batch_size
        self._max_attempts = max_attempts
        self._semaphore = asyncio.Semaphore(concurrency)

    async def claim_due(self) -> list[Claim]:
        now = utcnow()
        claims = []
        async with self._db.session() as session:
            rows = await session.execute(
                select(WebhookDelivery, Project)
                .join(Project, Project.id == WebhookDelivery.project_id)
                .where(
                    WebhookDelivery.status == DeliveryStatus.PENDING,
                    WebhookDelivery.next_attempt_at <= now,
                )
                .order_by(WebhookDelivery.next_attempt_at)
                .limit(self._batch_size)
                .with_for_update(skip_locked=True, of=WebhookDelivery)
            )
            for delivery, project in rows:
                if not project.webhook_url or not project.webhook_secret:
                    delivery.status = DeliveryStatus.FAILED
                    delivery.last_error = "webhook was removed"
                    continue
                delivery.attempts += 1
                delivery.next_attempt_at = now + LEASE
                claims.append(
                    Claim(
                        delivery.id,
                        delivery.event_type,
                        project.webhook_url,
                        project.webhook_secret,
                        delivery.payload,
                    )
                )
            await session.commit()
        return claims

    async def deliver(self, claim: Claim) -> None:
        body = claim.payload.encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "X-SentinelFlow-Event": claim.event_type,
            "X-SentinelFlow-Delivery": str(claim.delivery_id),
            "X-SentinelFlow-Signature": sign(claim.secret, int(time.time()), body),
        }
        status: int | None = None
        error: str | None = None
        permanent = False
        try:
            async with self._semaphore:
                status = await self._sender.send(claim.url, body, headers)
        except BlockedDestination as exc:
            error, permanent = f"destination not allowed: {exc}", True
        except (ProbeError, httpx.HTTPError, OSError) as exc:
            error = f"{type(exc).__name__}: {exc}"[:500]
        if status is not None and not 200 <= status < 300:
            error = f"HTTP {status}"
            permanent = not is_retryable(status)
        await self._record(claim, status, error, permanent)

    async def _record(
        self, claim: Claim, status: int | None, error: str | None, permanent: bool
    ) -> None:
        async with self._db.session() as session:
            delivery = await session.get(WebhookDelivery, claim.delivery_id, with_for_update=True)
            if delivery is None:
                return
            delivery.last_status_code = status
            delivery.last_error = error
            if error is None:
                delivery.status = DeliveryStatus.DELIVERED
                delivery.delivered_at = utcnow()
                outcome = "delivered"
            elif permanent or delivery.attempts >= self._max_attempts:
                delivery.status = DeliveryStatus.FAILED
                outcome = "failed"
            else:
                delivery.next_attempt_at = utcnow() + backoff(delivery.attempts)
                outcome = "retry"
            await session.commit()
        WEBHOOK_DELIVERIES.labels(outcome).inc()
        logger.info("delivery %s %s (%s)", claim.delivery_id, outcome, error or status)

    async def run_once(self) -> int:
        claims = await self.claim_due()
        await asyncio.gather(*(self.deliver(c) for c in claims))
        return len(claims)

    async def run(
        self, stop: asyncio.Event, poll_interval: float = 1.0, heartbeat: Heartbeat | None = None
    ) -> None:
        while not stop.is_set():
            if heartbeat is not None:
                heartbeat.beat()
            try:
                handled = await self.run_once()
            except Exception:
                logger.exception("notifier iteration failed; will retry")
                handled = 0
            if handled < self._batch_size:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_interval)


async def main() -> None:
    settings = NotifierSettings()
    configure_logging(settings.log_level)
    serve_metrics(settings.metrics_port)
    private_hosts = {h.strip().lower() for h in settings.webhook_private_hosts.split(",")}
    policy = DestinationPolicy(private_hosts=frozenset(h for h in private_hosts if h))
    database = Database(settings.database_url)
    sender = HttpSender(policy, settings.request_timeout)
    notifier = Notifier(
        database, sender, batch_size=settings.batch_size, max_attempts=settings.max_attempts
    )
    stop = asyncio.Event()
    install_signal_handlers(stop)
    logger.info("webhook notifier started")
    try:
        await notifier.run(stop, settings.poll_interval, heartbeat=Heartbeat())
    finally:
        await sender.close()
        await database.dispose()


if __name__ == "__main__":
    asyncio.run(main())
