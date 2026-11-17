"""Shared runtime for scanner workers: consume requests, publish results."""

import asyncio
import logging
from collections.abc import Awaitable, Callable

from sentinelflow_common.bus import AnyEvent, JetStreamBus, install_signal_handlers
from sentinelflow_common.events import (
    ScanCompleted,
    ScanRequested,
    ScanStatus,
    Subjects,
    TargetType,
)
from sentinelflow_common.health import Heartbeat
from sentinelflow_common.metrics import SCAN_DURATION, SCANS, serve_metrics

logger = logging.getLogger(__name__)

ScanHandler = Callable[[ScanRequested], Awaitable[ScanCompleted | None]]


def configure_logging(level: str) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")


async def run_scanner_worker(
    *,
    name: str,
    target_type: TargetType,
    handle: ScanHandler,
    nats_url: str,
    ack_wait: float = 60.0,
    batch: int = 10,
    metrics_port: int = 0,
) -> None:
    """Consume ``scan.requested.<target_type>`` and publish ``scan.completed``.

    ``ack_wait`` must exceed the worst-case time to process a whole fetched
    batch, otherwise JetStream redelivers messages that are still in progress.
    """
    serve_metrics(metrics_port)
    for status in ScanStatus:  # export at 0 so rate() sees the first event
        SCANS.labels(name, status.value)
    bus = await JetStreamBus.connect(nats_url, name=name)
    await bus.ensure_stream()

    async def on_event(event: AnyEvent) -> None:
        if not isinstance(event, ScanRequested) or event.target_type != target_type:
            return
        logger.info("scanning %s", event.scan_id)
        with SCAN_DURATION.labels(name).time():
            result = await handle(event)
        if result is None:
            return
        SCANS.labels(name, result.status.value).inc()
        # Deterministic msg id: a redelivered request yields a deduplicated result.
        await bus.publish_event(
            Subjects.SCAN_COMPLETED, result, msg_id=f"{event.scan_id}.completed"
        )
        logger.info(
            "scan %s %s with %d findings", event.scan_id, result.status, len(result.findings)
        )

    stop = asyncio.Event()
    install_signal_handlers(stop)
    try:
        await bus.consume(
            Subjects.scan_requested(target_type),
            name,
            on_event,
            stop,
            batch=batch,
            ack_wait=ack_wait,
            heartbeat=Heartbeat(),
        )
    finally:
        await bus.close()
