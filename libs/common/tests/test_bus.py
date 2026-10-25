from dataclasses import dataclass, field
from uuid import uuid4

import pytest

from sentinelflow_common.bus import AnyEvent, dispatch_message, retry_delay
from sentinelflow_common.events import ScanRequested, TargetType, encode_event


@dataclass
class FakeMessage:
    data: bytes
    calls: list[str] = field(default_factory=list)
    nak_delay: float | None = None

    async def ack(self) -> None:
        self.calls.append("ack")

    async def nak(self, delay: float | None = None) -> None:
        self.calls.append("nak")
        self.nak_delay = delay

    async def term(self) -> None:
        self.calls.append("term")


def _event_bytes() -> bytes:
    return encode_event(
        ScanRequested(
            scan_id=uuid4(),
            project_id=uuid4(),
            target_type=TargetType.DOCKERFILE,
            target="FROM alpine",
        )
    )


async def test_successful_handler_acks() -> None:
    received: list[AnyEvent] = []

    async def handler(event: AnyEvent) -> None:
        received.append(event)

    msg = FakeMessage(_event_bytes())
    await dispatch_message(msg, handler)
    assert msg.calls == ["ack"]
    assert isinstance(received[0], ScanRequested)


async def test_failing_handler_naks_with_backoff() -> None:
    async def handler(event: AnyEvent) -> None:
        raise RuntimeError("database down")

    msg = FakeMessage(_event_bytes())
    await dispatch_message(msg, handler, num_delivered=3)
    assert msg.calls == ["nak"]
    assert msg.nak_delay == 4.0


@pytest.mark.parametrize("payload", [b"not json", b"{}", b'{"event_type": "unknown"}'])
async def test_malformed_message_is_terminated_not_retried(payload: bytes) -> None:
    async def handler(event: AnyEvent) -> None:
        raise AssertionError("must not be called")

    msg = FakeMessage(payload)
    await dispatch_message(msg, handler)
    assert msg.calls == ["term"]


@pytest.mark.parametrize(("n", "delay"), [(0, 1.0), (1, 1.0), (2, 2.0), (5, 16.0), (20, 60.0)])
def test_retry_delay_is_exponential_and_capped(n: int, delay: float) -> None:
    assert retry_delay(n) == delay
