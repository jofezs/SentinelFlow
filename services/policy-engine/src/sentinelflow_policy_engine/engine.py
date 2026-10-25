from typing import Any, Protocol

from sentinelflow_common.events import (
    PolicyEvaluated,
    PolicyEvaluationRequested,
    PolicyViolation,
)


class DecisionClient(Protocol):
    async def decide(self, input_doc: dict[str, Any]) -> dict[str, Any]: ...


def build_input(request: PolicyEvaluationRequested) -> dict[str, Any]:
    return {
        "scan": {
            "target_type": request.target_type.value,
            "target": request.target,
            "scanner": request.scanner,
        },
        "findings": [f.model_dump(mode="json") for f in request.findings],
        "config": request.config.model_dump(mode="json"),
    }


def to_event(request: PolicyEvaluationRequested, result: dict[str, Any]) -> PolicyEvaluated:
    """Validate OPA's output strictly: a malformed decision must never pass silently."""
    allow = result.get("allow")
    if not isinstance(allow, bool):
        raise ValueError(f"policy decision has no boolean 'allow': {result!r}")
    violations = sorted(
        (PolicyViolation.model_validate(v) for v in result.get("violations", [])),
        key=lambda v: (-v.severity.rank, v.policy_id),
    )
    if allow and violations:
        raise ValueError("policy decision allows the scan but lists violations")
    return PolicyEvaluated(
        scan_id=request.scan_id,
        project_id=request.project_id,
        passed=allow,
        violations=tuple(violations),
    )


async def evaluate(client: DecisionClient, request: PolicyEvaluationRequested) -> PolicyEvaluated:
    return to_event(request, await client.decide(build_input(request)))
