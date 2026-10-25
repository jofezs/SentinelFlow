"""Gateway background worker: outbox relay + scan results ingestion.

Run with: python -m sentinelflow_gateway.worker
"""

import asyncio
import logging

from sentinelflow_common.bus import JetStreamBus, install_signal_handlers
from sentinelflow_common.events import Subjects
from sentinelflow_common.health import Heartbeat
from sentinelflow_gateway.config import WorkerSettings
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.ingest import ResultsIngester
from sentinelflow_gateway.outbox import OutboxRelay

logger = logging.getLogger("sentinelflow_gateway.worker")


async def main() -> None:
    settings = WorkerSettings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    database = Database(settings.database_url)
    bus = await JetStreamBus.connect(settings.nats_url, name="gateway-worker")
    await bus.ensure_stream()

    stop = asyncio.Event()
    install_signal_handlers(stop)
    relay = OutboxRelay(database, bus, batch_size=settings.relay_batch_size)
    heartbeat = Heartbeat()  # beaten by both loops; see sentinelflow_common.health

    logger.info("gateway worker started")
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                relay.run(stop, poll_interval=settings.relay_poll_interval, heartbeat=heartbeat)
            )
            tg.create_task(
                bus.consume(
                    Subjects.SCAN_COMPLETED,
                    "gateway-results",
                    ResultsIngester(database),
                    stop,
                    heartbeat=heartbeat,
                )
            )
    finally:
        await bus.close()
        await database.dispose()
        logger.info("gateway worker stopped")


if __name__ == "__main__":
    asyncio.run(main())
