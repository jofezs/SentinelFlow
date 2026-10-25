import uuid

import httpx
import pytest
from sqlalchemy import select

from sentinelflow_common.events import (
    Finding,
    PolicyEvaluated,
    PolicyEvaluationRequested,
    PolicyViolation,
    ScanCompleted,
    ScanStatus,
    Severity,
    TargetType,
    decode_event,
)
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.ingest import ResultsIngester
from sentinelflow_gateway.models import OutboxEvent

from .conftest import submit_scan

FINDING = Finding(rule_id="SF001", title="root", severity=Severity.HIGH, location="line 1")


def _completed(scan: dict[str, str], status: ScanStatus = ScanStatus.SUCCEEDED) -> ScanCompleted:
    return ScanCompleted(
        scan_id=uuid.UUID(scan["id"]),
        project_id=uuid.UUID(scan["project_id"]),
        target_type=TargetType.DOCKERFILE,
        scanner="dockerfile:hadolint+sf-rules",
        status=status,
        findings=(FINDING,) if status == ScanStatus.SUCCEEDED else (),
        error=None if status == ScanStatus.SUCCEEDED else "boom",
    )


def _decision(scan: dict[str, str], passed: bool) -> PolicyEvaluated:
    violations = (
        ()
        if passed
        else (
            PolicyViolation(policy_id="no_root_container", message="root", severity=Severity.HIGH),
        )
    )
    return PolicyEvaluated(
        scan_id=uuid.UUID(scan["id"]),
        project_id=uuid.UUID(scan["project_id"]),
        passed=passed,
        violations=violations,
    )


async def _policy_requests(database: Database) -> list[PolicyEvaluationRequested]:
    async with database.session() as session:
        rows = await session.scalars(
            select(OutboxEvent).where(OutboxEvent.subject == "policy.requested")
        )
        events = [decode_event(r.payload) for r in rows]
    assert all(isinstance(e, PolicyEvaluationRequested) for e in events)
    return events  # type: ignore[return-value]


class TestPolicyConfigApi:
    async def test_catalog_lists_policies_with_param_schemas(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        policies = (await client.get("/v1/policies", headers=api_headers)).json()
        by_id = {p["id"]: p for p in policies}
        assert "no_root_container" in by_id
        assert by_id["no_root_container"]["applies_to"] == ["dockerfile"]
        assert by_id["no_root_container"]["params_schema"] is None
        schema = by_id["severity_threshold"]["params_schema"]
        assert "fail_on" in schema["properties"]

    async def test_catalog_requires_auth(self, client: httpx.AsyncClient) -> None:
        assert (await client.get("/v1/policies")).status_code == 401

    async def test_default_config_is_all_policies(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        resp = await client.get("/v1/projects/me/policy", headers=api_headers)
        assert resp.json() == {"enabled": None, "params": {}}

    async def test_update_config_round_trips_with_defaults(
        self, client: httpx.AsyncClient, api_headers: dict[str, str]
    ) -> None:
        body = {"enabled": ["severity_threshold", "no_fixable_vulns"], "params": {
            "severity_threshold": {"fail_on": "high"},
            "no_fixable_vulns": {},
        }}  # fmt: skip
        resp = await client.put("/v1/projects/me/policy", json=body, headers=api_headers)
        assert resp.status_code == 200, resp.text
        expected = {
            "enabled": ["severity_threshold", "no_fixable_vulns"],
            "params": {
                "severity_threshold": {"fail_on": "high"},
                "no_fixable_vulns": {"min_severity": "high"},
            },
        }
        assert resp.json() == expected
        assert (await client.get("/v1/projects/me/policy", headers=api_headers)).json() == expected

    @pytest.mark.parametrize(
        "body",
        [
            {"enabled": ["not_a_policy"]},
            {"params": {"severity_threshold": {"fail_on": "apocalyptic"}}},
            {"params": {"no_secrets": {"anything": 1}}},
            {"enabled": [], "surprise": True},
        ],
    )
    async def test_invalid_config_rejected(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], body: dict[str, object]
    ) -> None:
        resp = await client.put("/v1/projects/me/policy", json=body, headers=api_headers)
        assert resp.status_code == 422


class TestPolicyFlow:
    async def test_successful_scan_requests_policy_with_config_snapshot(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        await client.put(
            "/v1/projects/me/policy",
            json={"enabled": ["no_root_container"]},
            headers=api_headers,
        )
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        await ResultsIngester(database)(_completed(scan))

        [request] = await _policy_requests(database)
        assert str(request.scan_id) == scan["id"]
        assert request.findings == (FINDING,)
        assert request.config.enabled == ("no_root_container",)
        assert request.scanner == "dockerfile:hadolint+sf-rules"

    async def test_failed_scan_is_not_policy_evaluated(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        await ResultsIngester(database)(_completed(scan, ScanStatus.FAILED))
        assert await _policy_requests(database) == []

    async def test_duplicate_scan_result_does_not_request_policy_twice(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        ingester = ResultsIngester(database)
        await ingester(_completed(scan))
        await ingester(_completed(scan))
        assert len(await _policy_requests(database)) == 1

    async def test_policy_decision_is_recorded_once(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        scan = await submit_scan(client, api_headers, "dockerfile", "FROM alpine")
        ingester = ResultsIngester(database)
        await ingester(_completed(scan))

        pending = (await client.get(f"/v1/scans/{scan['id']}", headers=api_headers)).json()
        assert pending["policy_passed"] is None

        await ingester(_decision(scan, passed=False))
        await ingester(_decision(scan, passed=True))  # late duplicate must not flip it

        body = (await client.get(f"/v1/scans/{scan['id']}", headers=api_headers)).json()
        assert body["policy_passed"] is False
        assert body["policy_violations"] == [
            {"policy_id": "no_root_container", "message": "root", "severity": "high"}
        ]
        assert body["policy_evaluated_at"] is not None

    async def test_filter_scans_by_policy_outcome(
        self, client: httpx.AsyncClient, api_headers: dict[str, str], database: Database
    ) -> None:
        ingester = ResultsIngester(database)
        passing = await submit_scan(client, api_headers, "dockerfile", "FROM a")
        failing = await submit_scan(client, api_headers, "dockerfile", "FROM b")
        await submit_scan(client, api_headers, "dockerfile", "FROM c")  # never evaluated
        for scan, passed in ((passing, True), (failing, False)):
            await ingester(_completed(scan))
            await ingester(_decision(scan, passed=passed))

        def ids(resp: httpx.Response) -> list[str]:
            return [s["id"] for s in resp.json()["items"]]

        ok = await client.get("/v1/scans?policy_passed=true", headers=api_headers)
        bad = await client.get("/v1/scans?policy_passed=false", headers=api_headers)
        assert ids(ok) == [passing["id"]]
        assert ids(bad) == [failing["id"]]
