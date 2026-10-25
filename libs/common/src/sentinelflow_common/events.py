"""Event contracts exchanged over the message bus.

Every message on the bus is one of the event models below. Services never
share a database; they communicate only through these versioned contracts,
which keeps them independently deployable.

Flow:
    gateway   --scan.requested.<target>-->  scanners
    scanners  --scan.completed----------->  gateway (stores results)
    gateway   --policy.requested--------->  policy engine (findings + project policy config)
    policy    --policy.evaluated--------->  gateway (stores decision), notifier
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

SCHEMA_VERSION = 1


class TargetType(StrEnum):
    IMAGE = "image"
    DOCKERFILE = "dockerfile"
    API_ENDPOINT = "api_endpoint"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for comparisons; higher is more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ScanStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Subjects:
    """Message bus subjects (NATS-style, dot separated)."""

    SCAN_REQUESTED = "scan.requested"
    SCAN_COMPLETED = "scan.completed"
    POLICY_REQUESTED = "policy.requested"
    POLICY_EVALUATED = "policy.evaluated"

    @staticmethod
    def scan_requested(target_type: TargetType) -> str:
        return f"{Subjects.SCAN_REQUESTED}.{target_type.value}"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Finding(_Model):
    rule_id: str = Field(min_length=1, examples=["DL3007", "CVE-2024-3094"])
    title: str
    severity: Severity
    description: str = ""
    location: str | None = Field(default=None, description="File:line, package, or header name")
    remediation: str | None = None
    fix_available: bool | None = Field(
        default=None, description="For vulnerabilities: whether a fixed version exists"
    )


class _EventBase(_Model):
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: int = SCHEMA_VERSION
    scan_id: UUID


class ScanRequested(_EventBase):
    event_type: Literal["scan.requested"] = "scan.requested"
    project_id: UUID
    target_type: TargetType
    target: str = Field(
        min_length=1,
        description="Image reference, Dockerfile content, or endpoint URL depending on target_type",
    )


class ScanCompleted(_EventBase):
    event_type: Literal["scan.completed"] = "scan.completed"
    project_id: UUID
    target_type: TargetType
    scanner: str = Field(examples=["trivy", "hadolint", "api-probe"])
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    error: str | None = None

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


class PolicyConfig(_Model):
    """A project's policy selection. ``enabled=None`` means every policy applies."""

    enabled: tuple[str, ...] | None = None
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)


class PolicyEvaluationRequested(_EventBase):
    """Carries everything the (stateless) policy engine needs, including a
    snapshot of the project's policy config at evaluation time, so each
    decision records exactly which rules it was judged against."""

    event_type: Literal["policy.requested"] = "policy.requested"
    project_id: UUID
    target_type: TargetType
    target: str
    scanner: str
    findings: tuple[Finding, ...] = ()
    config: PolicyConfig = Field(default_factory=PolicyConfig)


class PolicyViolation(_Model):
    policy_id: str
    message: str
    severity: Severity


class PolicyEvaluated(_EventBase):
    event_type: Literal["policy.evaluated"] = "policy.evaluated"
    project_id: UUID
    passed: bool
    violations: tuple[PolicyViolation, ...] = ()


AnyEvent = ScanRequested | ScanCompleted | PolicyEvaluationRequested | PolicyEvaluated

Event = Annotated[AnyEvent, Field(discriminator="event_type")]

_event_adapter: TypeAdapter[Event] = TypeAdapter(Event)


def encode_event(event: AnyEvent) -> bytes:
    """Serialize an event for publishing on the bus."""
    return event.model_dump_json().encode()


def decode_event(payload: bytes | str) -> AnyEvent:
    """Parse a bus payload into the correct event model (validated)."""
    return _event_adapter.validate_json(payload)
