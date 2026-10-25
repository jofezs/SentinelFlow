import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelflow_common.events import TargetType
from sentinelflow_gateway.db import Base


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
