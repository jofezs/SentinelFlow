from dataclasses import dataclass, field
from uuid import uuid4

import pytest
from prometheus_client import REGISTRY

from sentinelflow_common.bus import AnyEvent, dispatch_message, retry_delay, split_credentials
from sentinelflow_common.events import (
    ScanCompleted,
    ScanRequested,
    ScanStatus,
    TargetType,
    encode_event,
)


@dataclass
class FakeMessage:
    data: bytes
    subject: str = "scan.requested.dockerfile"
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


async def test_outcomes_are_counted() -> None:
    async def ok(event: AnyEvent) -> None:
        pass

    def count(outcome: str) -> float:
        labels = {"consumer": "metrics-test", "outcome": outcome}
        return REGISTRY.get_sample_value("sentinelflow_messages_total", labels) or 0.0

    before_ack, before_term = count("ack"), count("term")
    await dispatch_message(FakeMessage(_event_bytes()), ok, consumer="metrics-test")
    await dispatch_message(FakeMessage(b"junk"), ok, consumer="metrics-test")
    assert count("ack") == before_ack + 1
    assert count("term") == before_term + 1


@pytest.mark.parametrize(("n", "delay"), [(0, 1.0), (1, 1.0), (2, 2.0), (5, 16.0), (20, 60.0)])
def test_retry_delay_is_exponential_and_capped(n: int, delay: float) -> None:
    assert retry_delay(n) == delay


def _completed_bytes(target_type: TargetType) -> bytes:
    return encode_event(
        ScanCompleted(
            scan_id=uuid4(),
            project_id=uuid4(),
            target_type=target_type,
            scanner="trivy",
            status=ScanStatus.SUCCEEDED,
        )
    )


async def test_scan_result_on_its_own_subject_is_handled() -> None:
    received: list[AnyEvent] = []

    async def handler(event: AnyEvent) -> None:
        received.append(event)

    msg = FakeMessage(_completed_bytes(TargetType.IMAGE), subject="scan.completed.image")
    await dispatch_message(msg, handler)
    assert msg.calls == ["ack"] and len(received) == 1


async def test_scan_result_claiming_another_target_type_is_dropped() -> None:
    """NATS lets the API scanner publish only on scan.completed.api_endpoint; a payload
    there that claims to be an image result must never reach the handler."""
    received: list[AnyEvent] = []

    async def handler(event: AnyEvent) -> None:
        received.append(event)

    msg = FakeMessage(_completed_bytes(TargetType.IMAGE), subject="scan.completed.api_endpoint")
    await dispatch_message(msg, handler)
    assert msg.calls == ["term"]
    assert received == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("nats://nats:4222", ("nats://nats:4222", None, None)),
        ("nats://scanner-api:s3cr%40t@nats:4222", ("nats://nats:4222", "scanner-api", "s3cr@t")),
        ("nats://user@127.0.0.1", ("nats://127.0.0.1", "user", None)),
    ],
)
def test_credentials_are_split_out_of_the_url(
    url: str, expected: tuple[str, str | None, str | None]
) -> None:
    assert split_credentials(url) == expected
