"""Request and response models for the public HTTP API."""

import re
import uuid
from datetime import datetime
from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinelflow_common.events import (
    Finding,
    PolicyConfig,
    PolicyViolation,
    Severity,
    TargetType,
)
from sentinelflow_common.policies import validate_config
from sentinelflow_gateway.models import ScanState

MAX_DOCKERFILE_CHARS = 64 * 1024
MAX_URL_CHARS = 2048
MAX_IMAGE_REF_CHARS = 255

# [registry[:port]/]path[/path...][:tag][@sha256:digest]
# As in Docker, the first component is a registry only if it is "localhost", contains a ".",
# or has a port. Must start with an alphanumeric, which also blocks CLI-flag injection.
_HOST = r"[a-zA-Z0-9][a-zA-Z0-9-]*"
_IMAGE_REF_RE = re.compile(
    rf"^(?:(?:localhost|{_HOST}(?:\.{_HOST})+)(?::[0-9]{{1,5}})?/|{_HOST}:[0-9]{{1,5}}/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[\w][\w.-]{0,127})?"
    r"(?:@sha256:[a-f0-9]{64})?$"
)
_FROM_RE = re.compile(r"^\s*FROM\s+\S+", re.IGNORECASE | re.MULTILINE)


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Response(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProjectCreate(_Request):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$", examples=["payments-api"])


class ProjectRead(_Response):
    id: uuid.UUID
    name: str
    created_at: datetime


class ProjectCreated(ProjectRead):
    api_key: str = Field(description="Shown only once. Store it securely.")


class ScanCreate(_Request):
    target_type: TargetType
    target: str = Field(min_length=1, max_length=MAX_DOCKERFILE_CHARS)

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        match self.target_type:
            case TargetType.IMAGE:
                _validate_image_ref(self.target)
            case TargetType.DOCKERFILE:
                if not _FROM_RE.search(self.target):
                    raise ValueError("Dockerfile must contain a FROM instruction")
            case TargetType.API_ENDPOINT:
                _validate_endpoint_url(self.target)
        return self


def _validate_image_ref(ref: str) -> None:
    if len(ref) > MAX_IMAGE_REF_CHARS or not _IMAGE_REF_RE.fullmatch(ref):
        raise ValueError("invalid container image reference")


def _validate_endpoint_url(url: str) -> None:
    # Syntactic checks only. SSRF protection (resolving the host and rejecting
    # private/link-local ranges) happens in the API scanner at request time,
    # since DNS answers can change between submission and scan.
    if len(url) > MAX_URL_CHARS:
        raise ValueError("URL too long")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parts.hostname:
        raise ValueError("URL must include a host")
    if parts.username or parts.password:
        raise ValueError("URL must not contain credentials")


class ScanRead(_Response):
    id: uuid.UUID
    project_id: uuid.UUID
    target_type: TargetType
    target: str
    status: ScanState
    scanner: str | None = None
    max_severity: Severity | None = None
    finding_count: int = 0
    policy_passed: bool | None = Field(
        default=None, description="null until the policy engine has evaluated the scan"
    )
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


class ScanDetail(ScanRead):
    findings: list[Finding] = []
    error: str | None = None
    policy_violations: list[PolicyViolation] = []
    policy_evaluated_at: datetime | None = None

    @field_validator("findings", "policy_violations", mode="before")
    @classmethod
    def _none_to_empty(cls, value: object) -> object:
        return [] if value is None else value


class PolicyRead(BaseModel):
    id: str
    title: str
    description: str
    applies_to: list[TargetType]
    params_schema: dict[str, Any] | None = Field(
        description="JSON Schema of the policy's parameters (null if it takes none)"
    )


class PolicyConfigRead(BaseModel):
    enabled: list[str] | None = Field(description="Enabled policy IDs; null means all policies")
    params: dict[str, dict[str, Any]]


class PolicyConfigUpdate(_Request):
    enabled: list[str] | None = Field(default=None, examples=[["severity_threshold", "no_secrets"]])
    params: dict[str, dict[str, Any]] = Field(
        default_factory=dict, examples=[{"severity_threshold": {"fail_on": "high"}}]
    )

    def to_config(self) -> PolicyConfig:
        """Validate against the policy catalog (raises ValueError)."""
        return validate_config(self.enabled, self.params)


class ScanList(BaseModel):
    items: list[ScanRead]
    total: int
    limit: int
    offset: int
