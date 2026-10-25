import logging
from typing import Protocol

from sentinelflow_common.events import PolicyEvaluated, ScanCompleted, ScanRequested, encode_event

logger = logging.getLogger(__name__)

AnyEvent = ScanRequested | ScanCompleted | PolicyEvaluated


class EventPublisher(Protocol):
    async def publish(self, subject: str, event: AnyEvent) -> None: ...

    async def close(self) -> None: ...


class LoggingPublisher:
    """Placeholder publisher that only logs events (replaced by NATS in Phase 2)."""

    async def publish(self, subject: str, event: AnyEvent) -> None:
        logger.info("publish %s %s", subject, encode_event(event).decode())

    async def close(self) -> None:
        return None
