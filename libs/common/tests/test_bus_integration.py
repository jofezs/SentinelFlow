"""Round-trip tests against a real NATS server (skipped unless one is configured).

Run locally with:  docker run -d -p 4222:4222 nats:2.10-alpine -js
and SENTINELFLOW_TEST_NATS_URL=nats://127.0.0.1:4222
"""

import asyncio
import os
from uuid import uuid4

import pytest

from sentinelflow_common.bus import AnyEvent, JetStreamBus
from sentinelflow_common.events import ScanRequested, Subjects, TargetType

NATS_URL = os.environ.get("SENTINELFLOW_TEST_NATS_URL")
pytestmark = pytest.mark.skipif(not NATS_URL, reason="SENTINELFLOW_TEST_NATS_URL not set")


async def test_publish_consume_round_trip_and_dedup() -> None:
    assert NATS_URL
    bus = await JetStreamBus.connect(NATS_URL, name="test")
    await bus.ensure_stream()
    await bus.ensure_stream()  # idempotent

    event = ScanRequested(
        scan_id=uuid4(), project_id=uuid4(), target_type=TargetType.IMAGE, target="alpine:3"
    )
    subject = Subjects.scan_requested(TargetType.IMAGE)
    await bus.publish_event(subject, event)
    await bus.publish_event(subject, event)  # same msg id -> dropped by JetStream

    received: list[AnyEvent] = []
    stop = asyncio.Event()

    async def handler(e: AnyEvent) -> None:
        if e.scan_id == event.scan_id:
            received.append(e)

    task = asyncio.create_task(bus.consume(subject, f"test-{uuid4().hex[:8]}", handler, stop))
    await asyncio.sleep(2.5)
    stop.set()
    await task
    await bus.close()

    assert received == [event]
