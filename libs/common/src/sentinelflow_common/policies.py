"""Policy catalog: the single source of truth for policy IDs and parameters.

The Rego implementation lives in services/policy-engine/policies; a test there
asserts that every Rego policy package matches an entry here (and vice versa).
"""

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinelflow_common.events import PolicyConfig, Severity, TargetType

ALL_TARGETS = frozenset(TargetType)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SeverityThresholdParams(_Params):
    fail_on: Severity = Severity.CRITICAL


class NoFixableVulnsParams(_Params):
    min_severity: Severity = Severity.HIGH


@dataclass(frozen=True)
class PolicySpec:
    id: str
    title: str
    description: str
    applies_to: frozenset[TargetType]
    params: type[_Params] | None = field(default=None)


POLICIES: dict[str, PolicySpec] = {
    spec.id: spec
    for spec in (
        PolicySpec(
            "severity_threshold",
            "Severity threshold",
            "Fail if any finding is at or above the configured severity.",
            ALL_TARGETS,
            SeverityThresholdParams,
        ),
        PolicySpec(
            "no_secrets",
            "No embedded secrets",
            "Fail if secrets are baked into the Dockerfile or image.",
            frozenset({TargetType.DOCKERFILE, TargetType.IMAGE}),
        ),
        PolicySpec(
            "no_root_container",
            "Non-root container",
            "Fail if the final image runs as root.",
            frozenset({TargetType.DOCKERFILE}),
        ),
        PolicySpec(
            "supply_chain",
            "Verified downloads",
            "Fail on curl | sh, unverified remote ADD, or disabled TLS verification.",
            frozenset({TargetType.DOCKERFILE}),
        ),
        PolicySpec(
            "no_fixable_vulns",
            "No fixable vulnerabilities",
            "Fail if the image has vulnerabilities at or above min_severity that have a fix.",
            frozenset({TargetType.IMAGE}),
            NoFixableVulnsParams,
        ),
        PolicySpec(
            "https_required",
            "HTTPS required",
            "Fail on plaintext HTTP, weak TLS, or an invalid certificate.",
            frozenset({TargetType.API_ENDPOINT}),
        ),
        PolicySpec(
            "hsts_required",
            "HSTS required",
            "Fail if Strict-Transport-Security is missing.",
            frozenset({TargetType.API_ENDPOINT}),
        ),
        PolicySpec(
            "cors_restricted",
            "Restricted CORS",
            "Fail on reflected, null, or credentialed wildcard CORS origins.",
            frozenset({TargetType.API_ENDPOINT}),
        ),
    )
}


def validate_config(enabled: list[str] | None, params: dict[str, Any]) -> PolicyConfig:
    """Validate a user-supplied policy config and fill in parameter defaults.

    Raises ValueError with a readable message on unknown policies or bad params.
    """
    unknown = sorted(set(enabled or ()) - POLICIES.keys())
    if unknown:
        raise ValueError(f"unknown policies: {', '.join(unknown)}")
    normalized: dict[str, dict[str, Any]] = {}
    for policy_id, values in params.items():
        spec = POLICIES.get(policy_id)
        if spec is None:
            raise ValueError(f"unknown policy in params: {policy_id}")
        if spec.params is None:
            raise ValueError(f"policy {policy_id} takes no parameters")
        normalized[policy_id] = spec.params.model_validate(values).model_dump(mode="json")
    return PolicyConfig(
        enabled=tuple(dict.fromkeys(enabled)) if enabled is not None else None,
        params=normalized,
    )
