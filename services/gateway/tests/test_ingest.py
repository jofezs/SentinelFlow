import uuid

import httpx

from sentinelflow_common.events import (
    Finding,
    PolicyEvaluated,
    ScanCompleted,
    ScanStatus,
    Severity,
    TargetType,
)
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.ingest import ResultsIngester

from .conftest import submit_scan


def _completed(scan: dict[str, str], **overrides: object) -> ScanCompleted:
    fields: dict[str, object] = {
        "scan_id": uuid.UUID(scan["id"]),
        "project_id": uuid.UUID(scan["project_id"]),
        "target_type": TargetType.DOCKERFILE,
        "scanner": "hadolint",
        "status": ScanStatus.SUCCEEDED,
        "findings": (
            Finding(rule_id="SF001", title="Runs as root", severity=Severity.HIGH, location="1"),
            Finding(rule_id="DL3007", title="latest tag", severity=Severity.MEDIUM),
        ),
    }
    fields.update(overrides)
    return ScanCompleted.model_validate(fields)


async def test_completed_event_updates_scan(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
    await ResultsIngester(database)(_completed(scan))

    body = (await client.get(f"/v1/scans/{scan['id']}", headers=api_headers)).json()
    assert body["status"] == "completed"
    assert body["scanner"] == "hadolint"
    assert body["max_severity"] == "high"
    assert body["finding_count"] == 2
    assert body["findings"][0]["rule_id"] == "SF001"
    assert body["completed_at"] is not None

    listing = (await client.get("/v1/scans?status=completed", headers=api_headers)).json()
    assert listing["total"] == 1


async def test_failed_scan_records_error(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
    event = _completed(scan, status=ScanStatus.FAILED, findings=(), error="hadolint timed out")
    await ResultsIngester(database)(event)

    body = (await client.get(f"/v1/scans/{scan['id']}", headers=api_headers)).json()
    assert body["status"] == "failed"
    assert body["error"] == "hadolint timed out"
    assert body["max_severity"] is None


async def test_duplicate_delivery_is_ignored(
    client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
) -> None:
    scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
    ingester = ResultsIngester(database)
    await ingester(_completed(scan))
    # A later, different result for the same scan must not overwrite the first.
    await ingester(_completed(scan, status=ScanStatus.FAILED, findings=(), error="late"))

    body = (await client.get(f"/v1/scans/{scan['id']}", headers=api_headers)).json()
    assert body["status"] == "completed"
    assert body["finding_count"] == 2


async def test_unknown_scan_and_other_events_are_ignored(database: Database) -> None:
    ingester = ResultsIngester(database)
    ghost = {"id": str(uuid.uuid4()), "project_id": str(uuid.uuid4())}
    await ingester(_completed(ghost))  # no exception
    await ingester(PolicyEvaluated(scan_id=uuid.uuid4(), project_id=uuid.uuid4(), passed=True))
