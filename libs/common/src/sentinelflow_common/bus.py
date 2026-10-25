"""NATS JetStream helpers shared by all services.

Delivery semantics: at-least-once. Publishers set ``Nats-Msg-Id`` so JetStream
drops duplicates inside its duplicate window, and consumers must be idempotent
because a message is redelivered if it is not acked within ``ack_wait``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable
from typing import Protocol

import nats
import nats.errors
import nats.js.errors
from nats.aio.client import Client
from nats.js import JetStreamContext
from nats.js.api import AckPolicy, ConsumerConfig, RetentionPolicy, StorageType, StreamConfig
from pydantic import ValidationError

from sentinelflow_common.events import (
    PolicyEvaluated,
    ScanCompleted,
    ScanRequested,
    decode_event,
    encode_event,
)
from sentinelflow_common.health import Heartbeat

logger = logging.getLogger(__name__)

STREAM_NAME = "SENTINELFLOW"
STREAM_SUBJECTS = ["scan.>", "policy.>"]
DUPLICATE_WINDOW_SECONDS = 120.0
MAX_AGE_SECONDS = 7 * 24 * 3600.0

AnyEvent = ScanRequested | ScanCompleted | PolicyEvaluated
Handler = Callable[[AnyEvent], Awaitable[None]]


class Message(Protocol):
    """The subset of a JetStream message that ``dispatch_message`` needs."""

    data: bytes

    async def ack(self) -> None: ...

    async def nak(self, delay: float | None = None) -> None: ...

    async def term(self) -> None: ...


def retry_delay(num_delivered: int) -> float:
    """Exponential backoff for redelivery: 1s, 2s, 4s ... capped at 60s."""
    return float(min(60, 2 ** max(0, num_delivered - 1)))


async def dispatch_message(msg: Message, handler: Handler, num_delivered: int = 1) -> None:
    """Decode, handle, and ack a message.

    - Undecodable payloads are terminated (never redelivered): retrying cannot fix them.
    - Handler failures are nak'ed with backoff so JetStream redelivers them.
    """
    try:
        event = decode_event(msg.data)
    except ValidationError:
        logger.error("dropping malformed message: %r", msg.data[:200])
        await msg.term()
        return

    try:
        await handler(event)
    except Exception:
        logger.exception("handler failed for event %s (delivery %d)", event.event_id, num_delivered)
        await msg.nak(delay=retry_delay(num_delivered))
        return
    await msg.ack()


def install_signal_handlers(stop: asyncio.Event) -> None:
    """Set ``stop`` on SIGINT/SIGTERM so workers drain gracefully (e.g. on pod shutdown)."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # not supported on Windows
            loop.add_signal_handler(sig, stop.set)


class JetStreamBus:
    def __init__(self, nc: Client, js: JetStreamContext) -> None:
        self._nc = nc
        self._js = js

    @classmethod
    async def connect(cls, url: str, name: str) -> JetStreamBus:
        nc = await nats.connect(url, name=name, max_reconnect_attempts=-1)
        return cls(nc, nc.jetstream())

    async def ensure_stream(self) -> None:
        config = StreamConfig(
            name=STREAM_NAME,
            subjects=STREAM_SUBJECTS,
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            max_age=MAX_AGE_SECONDS,
            duplicate_window=DUPLICATE_WINDOW_SECONDS,
        )
        try:
            await self._js.stream_info(STREAM_NAME)
        except nats.js.errors.NotFoundError:
            await self._js.add_stream(config)
        else:
            await self._js.update_stream(config)

    async def publish(self, subject: str, payload: bytes, msg_id: str) -> None:
        await self._js.publish(subject, payload, headers={"Nats-Msg-Id": msg_id})

    async def publish_event(self, subject: str, event: AnyEvent, msg_id: str | None = None) -> None:
        await self.publish(subject, encode_event(event), msg_id or str(event.event_id))

    async def consume(
        self,
        subject: str,
        durable: str,
        handler: Handler,
        stop: asyncio.Event,
        *,
        batch: int = 10,
        ack_wait: float = 60.0,
        max_deliver: int = 5,
        heartbeat: Heartbeat | None = None,
    ) -> None:
        """Pull messages from a durable consumer until ``stop`` is set."""
        sub = await self._js.pull_subscribe(
            subject,
            durable=durable,
            config=ConsumerConfig(
                ack_policy=AckPolicy.EXPLICIT, ack_wait=ack_wait, max_deliver=max_deliver
            ),
        )
        logger.info("consuming %s as %s", subject, durable)
        try:
            while not stop.is_set():
                if heartbeat is not None:
                    heartbeat.beat()
                try:
                    msgs = await sub.fetch(batch, timeout=1.0)
                except (nats.errors.TimeoutError, TimeoutError):
                    continue
                for msg in msgs:
                    await dispatch_message(msg, handler, msg.metadata.num_delivered or 1)
        finally:
            # Release the pull subscription so connection drain completes promptly.
            with contextlib.suppress(Exception):
                await sub.unsubscribe()

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await self._nc.drain()
