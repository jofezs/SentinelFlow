from sentinelflow_common.events import (
    Finding,
    ScanCompleted,
    ScanRequested,
    ScanStatus,
    Severity,
    TargetType,
)
from sentinelflow_image_scanner import trivy

SCANNER_NAME = "image:trivy"
# Keeps scan.completed events well under the NATS 1 MB payload limit.
MAX_FINDINGS = 500


def prioritize(findings: list[Finding], limit: int = MAX_FINDINGS) -> list[Finding]:
    """Most severe first (fixable before unfixable); truncate with a marker finding."""
    ordered = sorted(
        findings,
        key=lambda f: (-f.severity.rank, (f.remediation or "").startswith("No fixed"), f.rule_id),
    )
    if len(ordered) <= limit:
        return ordered
    dropped = len(ordered) - (limit - 1)
    return [
        *ordered[: limit - 1],
        Finding(
            rule_id="SF-TRUNCATED",
            title=f"{dropped} lower-severity findings omitted",
            severity=Severity.INFO,
            description=f"The scan produced {len(ordered)} findings; only the most severe "
            f"{limit - 1} are stored.",
        ),
    ]


async def handle_request(
    event: ScanRequested,
    trivy_binary: str = "trivy",
    timeout: float = 600.0,
    cache_dir: str = "/var/cache/trivy",
) -> ScanCompleted | None:
    if event.target_type != TargetType.IMAGE:
        return None
    common = {
        "scan_id": event.scan_id,
        "project_id": event.project_id,
        "target_type": event.target_type,
        "scanner": SCANNER_NAME,
    }
    try:
        findings = await trivy.run(event.target, trivy_binary, timeout, cache_dir)
    except trivy.TrivyError as exc:
        return ScanCompleted(**common, status=ScanStatus.FAILED, error=str(exc))
    return ScanCompleted(
        **common, status=ScanStatus.SUCCEEDED, findings=tuple(prioritize(findings))
    )
