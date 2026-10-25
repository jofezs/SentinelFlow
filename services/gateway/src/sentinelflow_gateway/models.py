import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelflow_common.events import ScanRequested, Severity, TargetType, encode_event
from sentinelflow_gateway.db import Base

_JSON = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def _str_enum(enum_cls: type[StrEnum]) -> Enum:
    # Stored as VARCHAR (not a native PG enum) so adding values needs no migration lock.
    return Enum(
        enum_cls,
        native_enum=False,
        length=32,
        values_callable=lambda e: [m.value for m in e],
    )


class ScanState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanState.COMPLETED, ScanState.FAILED}


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(63), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKey(Base):
    """A project credential. Only a SHA-256 hash of the key is stored."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    prefix: Mapped[str] = mapped_column(String(12), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(lazy="raise")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_project_id_created_at", "project_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    target_type: Mapped[TargetType] = mapped_column(_str_enum(TargetType))
    target: Mapped[str] = mapped_column(Text)
    status: Mapped[ScanState] = mapped_column(_str_enum(ScanState), default=ScanState.QUEUED)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Populated when a scan.completed event is ingested.
    scanner: Mapped[str | None] = mapped_column(String(64))
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(_JSON)
    max_severity: Mapped[Severity | None] = mapped_column(_str_enum(Severity))
    error: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def finding_count(self) -> int:
        return len(self.findings or [])


class OutboxEvent(Base):
    """Transactional outbox: events are written in the same transaction as the
    state change that produced them, then relayed to the bus asynchronously.
    This guarantees a committed scan always has its event published, even if
    the broker was down at request time."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        Index(
            "ix_outbox_events_unpublished",
            "created_at",
            postgresql_where=text("published_at IS NULL"),
            sqlite_where=text("published_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)  # == event_id, used for dedup
    subject: Mapped[str] = mapped_column(String(255))
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @classmethod
    def for_event(cls, subject: str, event: ScanRequested) -> Self:
        return cls(id=event.event_id, subject=subject, payload=encode_event(event).decode())
