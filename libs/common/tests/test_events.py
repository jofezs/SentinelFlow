from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentinelflow_common.events import (
    Finding,
    PolicyEvaluated,
    PolicyViolation,
    ScanCompleted,
    ScanRequested,
    ScanStatus,
    Severity,
    Subjects,
    TargetType,
    decode_event,
    encode_event,
)


def _requested() -> ScanRequested:
    return ScanRequested(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.IMAGE,
        target="nginx:1.27",
    )


def test_round_trip_preserves_type_and_data() -> None:
    original = _requested()
    decoded = decode_event(encode_event(original))
    assert isinstance(decoded, ScanRequested)
    assert decoded == original


def test_decode_dispatches_on_event_type() -> None:
    completed = ScanCompleted(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.DOCKERFILE,
        scanner="hadolint",
        status=ScanStatus.SUCCEEDED,
        findings=(Finding(rule_id="DL3007", title="Using latest tag", severity=Severity.MEDIUM),),
    )
    evaluated = PolicyEvaluated(
        scan_id=completed.scan_id,
        project_id=completed.project_id,
        passed=False,
        violations=(PolicyViolation(policy_id="no-latest", message="x", severity=Severity.HIGH),),
    )
    assert isinstance(decode_event(encode_event(completed)), ScanCompleted)
    assert isinstance(decode_event(encode_event(evaluated)), PolicyEvaluated)


def test_unknown_fields_are_rejected() -> None:
    payload = _requested().model_dump(mode="json") | {"unexpected": "field"}
    with pytest.raises(ValidationError):
        ScanRequested.model_validate(payload)


def test_unknown_event_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        decode_event('{"event_type": "scan.deleted", "scan_id": "' + str(uuid4()) + '"}')


def test_empty_target_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanRequested(scan_id=uuid4(), project_id=uuid4(), target_type=TargetType.IMAGE, target="")


def test_events_are_immutable() -> None:
    event = _requested()
    with pytest.raises(ValidationError):
        event.target = "alpine:latest"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("severities", "expected"),
    [
        ((), None),
        ((Severity.LOW,), Severity.LOW),
        ((Severity.LOW, Severity.CRITICAL, Severity.MEDIUM), Severity.CRITICAL),
        ((Severity.INFO, Severity.HIGH), Severity.HIGH),
    ],
)
def test_max_severity(severities: tuple[Severity, ...], expected: Severity | None) -> None:
    event = ScanCompleted(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.IMAGE,
        scanner="trivy",
        status=ScanStatus.SUCCEEDED,
        findings=tuple(
            Finding(rule_id=f"R{i}", title="t", severity=s) for i, s in enumerate(severities)
        ),
    )
    assert event.max_severity() == expected


def test_subject_per_target_type() -> None:
    assert Subjects.scan_requested(TargetType.API_ENDPOINT) == "scan.requested.api_endpoint"
