from datetime import UTC, datetime

from sentinelflow_api_scanner import checks
from sentinelflow_api_scanner.probe import probe
from sentinelflow_api_scanner.ssrf import BlockedDestination, DestinationPolicy, ProbeError
from sentinelflow_common.events import ScanCompleted, ScanRequested, ScanStatus, TargetType

SCANNER_NAME = "api:probe"


async def handle_request(
    event: ScanRequested, policy: DestinationPolicy | None = None, timeout: float = 10.0
) -> ScanCompleted | None:
    if event.target_type != TargetType.API_ENDPOINT:
        return None
    common = {
        "scan_id": event.scan_id,
        "project_id": event.project_id,
        "target_type": event.target_type,
        "scanner": SCANNER_NAME,
    }
    try:
        result = await probe(event.target, policy or DestinationPolicy(), timeout)
    except BlockedDestination as exc:
        return ScanCompleted(
            **common, status=ScanStatus.FAILED, error=f"destination not allowed: {exc}"
        )
    except ProbeError as exc:
        return ScanCompleted(**common, status=ScanStatus.FAILED, error=str(exc)[:500])

    findings = sorted(checks.evaluate(result, datetime.now(UTC)), key=lambda f: -f.severity.rank)
    return ScanCompleted(**common, status=ScanStatus.SUCCEEDED, findings=tuple(findings))
