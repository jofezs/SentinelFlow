import httpx
from sqlalchemy import select

from sentinelflow_common.events import ScanRequested, decode_event
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import OutboxEvent
from sentinelflow_gateway.outbox import OutboxRelay

from .conftest import RecordingPublisher, submit_scan


async def _unpublished(database: Database) -> list[OutboxEvent]:
    async with database.session() as session:
        rows = await session.scalars(select(OutboxEvent).where(OutboxEvent.published_at.is_(None)))
        return list(rows)


async def test_relay_publishes_pending_events_in_order(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    first = await submit_scan(client, api_headers, "image", "nginx:1")
    second = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
    publisher = RecordingPublisher()

    assert await OutboxRelay(database, publisher).publish_pending() == 2

    subjects = [p[0] for p in publisher.published]
    assert subjects == ["scan.requested.image", "scan.requested.dockerfile"]
    events = [decode_event(p[1]) for p in publisher.published]
    assert [str(e.scan_id) for e in events] == [first["id"], second["id"]]
    # msg id == event id, so JetStream can deduplicate re-sends
    assert all(isinstance(e, ScanRequested) for e in events)
    assert [p[2] for p in publisher.published] == [str(e.event_id) for e in events]
    assert await _unpublished(database) == []


async def test_relay_is_noop_when_nothing_pending(database: Database) -> None:
    publisher = RecordingPublisher()
    assert await OutboxRelay(database, publisher).publish_pending() == 0
    assert publisher.published == []


async def test_already_published_events_are_not_resent(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    await submit_scan(client, api_headers, "image", "nginx:1")
    publisher = RecordingPublisher()
    relay = OutboxRelay(database, publisher)
    await relay.publish_pending()
    await relay.publish_pending()
    assert len(publisher.published) == 1


async def test_broker_outage_keeps_events_for_retry(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    await submit_scan(client, api_headers, "image", "nginx:1")
    await submit_scan(client, api_headers, "image", "nginx:2")

    failing = RecordingPublisher(fail_after=1)  # first publish succeeds, second fails
    try:
        await OutboxRelay(database, failing).publish_pending()
        raise AssertionError("expected ConnectionError")
    except ConnectionError:
        pass
    # Whole batch rolled back: nothing marked published, nothing lost.
    assert len(await _unpublished(database)) == 2

    healthy = RecordingPublisher()
    assert await OutboxRelay(database, healthy).publish_pending() == 2
    # The re-sent first event carries the same msg id as before -> deduped by JetStream.
    assert healthy.published[0][2] == failing.published[0][2]


async def test_batch_size_is_respected(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    for i in range(3):
        await submit_scan(client, api_headers, "image", f"app:{i}")
    publisher = RecordingPublisher()
    relay = OutboxRelay(database, publisher, batch_size=2)
    assert await relay.publish_pending() == 2
    assert await relay.publish_pending() == 1
