import asyncio
import contextlib
import logging
from typing import Protocol

from sqlalchemy import select

from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import OutboxEvent, utcnow

logger = logging.getLogger(__name__)


class RawPublisher(Protocol):
    async def publish(self, subject: str, payload: bytes, msg_id: str) -> None: ...


class OutboxRelay:
    """Moves committed outbox rows onto the message bus.

    Rows are claimed with ``FOR UPDATE SKIP LOCKED`` so several worker replicas
    can relay concurrently without double-processing. If publishing fails part
    way through a batch, the transaction rolls back and the batch is retried;
    rows that did reach the bus are deduplicated by JetStream via their msg id.
    """

    def __init__(self, database: Database, publisher: RawPublisher, batch_size: int = 100) -> None:
        self._db = database
        self._publisher = publisher
        self._batch_size = batch_size

    async def publish_pending(self) -> int:
        async with self._db.session() as session:
            rows = (
                await session.scalars(
                    select(OutboxEvent)
                    .where(OutboxEvent.published_at.is_(None))
                    .order_by(OutboxEvent.created_at)
                    .limit(self._batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
            for row in rows:
                await self._publisher.publish(row.subject, row.payload.encode(), str(row.id))
                row.published_at = utcnow()
            await session.commit()
        if rows:
            logger.info("relayed %d outbox event(s)", len(rows))
        return len(rows)

    async def run(self, stop: asyncio.Event, poll_interval: float = 0.5) -> None:
        while not stop.is_set():
            try:
                relayed = await self.publish_pending()
            except Exception:
                logger.exception("outbox relay failed; will retry")
                relayed = 0
            if relayed < self._batch_size:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_interval)
