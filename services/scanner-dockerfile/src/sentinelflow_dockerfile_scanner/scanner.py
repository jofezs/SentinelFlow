from sentinelflow_common.events import (
    Finding,
    ScanCompleted,
    ScanRequested,
    ScanStatus,
    TargetType,
)
from sentinelflow_dockerfile_scanner import hadolint, rules

SCANNER_NAME = "dockerfile:hadolint+sf-rules"


def _sort_key(finding: Finding) -> tuple[int, int]:
    line = finding.location.removeprefix("line ") if finding.location else ""
    return (-finding.severity.rank, int(line) if line.isdigit() else 0)


async def scan(content: str, hadolint_binary: str, timeout: float) -> list[Finding]:
    findings = rules.evaluate(content)
    findings += await hadolint.run(content, binary=hadolint_binary, timeout=timeout)
    return sorted(findings, key=_sort_key)


async def handle_request(
    event: ScanRequested, hadolint_binary: str = "hadolint", timeout: float = 30.0
) -> ScanCompleted | None:
    """Scan a Dockerfile request. Returns None for requests this scanner doesn't handle."""
    if event.target_type != TargetType.DOCKERFILE:
        return None
    common = {
        "scan_id": event.scan_id,
        "project_id": event.project_id,
        "target_type": event.target_type,
        "scanner": SCANNER_NAME,
    }
    try:
        findings = await scan(event.target, hadolint_binary, timeout)
    except hadolint.HadolintError as exc:
        return ScanCompleted(**common, status=ScanStatus.FAILED, error=str(exc))
    return ScanCompleted(**common, status=ScanStatus.SUCCEEDED, findings=tuple(findings))
