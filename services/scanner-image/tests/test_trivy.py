import json
import shutil
import tempfile
from typing import Any
from uuid import uuid4

import pytest

from sentinelflow_common.events import Finding, ScanRequested, ScanStatus, Severity, TargetType
from sentinelflow_image_scanner import trivy
from sentinelflow_image_scanner.scanner import handle_request, prioritize

TRIVY = shutil.which("trivy")


def _vuln(cve: str, pkg: str, severity: str, fixed: str | None = "1.1") -> dict[str, Any]:
    v: dict[str, Any] = {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "Severity": severity,
        "Title": f"{pkg} bug",
        "Description": "x" * 1000,
    }
    if fixed:
        v["FixedVersion"] = fixed
    return v


REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "alpine:3.18.0",
    "Results": [
        {
            "Target": "alpine:3.18.0 (alpine 3.18.0)",
            "Class": "os-pkgs",
            "Vulnerabilities": [
                _vuln("CVE-2022-48174", "busybox", "CRITICAL"),
                _vuln("CVE-2023-0001", "openssl", "MEDIUM", fixed=None),
                _vuln("CVE-2023-0002", "zlib", "UNKNOWN"),
            ],
        },
        {
            "Target": "usr/lib/app.jar",
            "Class": "lang-pkgs",
            # duplicate of the busybox CVE via another target -> deduplicated
            "Vulnerabilities": [_vuln("CVE-2022-48174", "busybox", "CRITICAL")],
        },
        {
            "Target": "/app/.env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 3,
                    "Match": "AWS_ACCESS_KEY_ID=AKIA****************",
                }
            ],
        },
        {"Target": "empty", "Class": "os-pkgs", "Vulnerabilities": None},
    ],
}


def test_parse_report_maps_and_deduplicates() -> None:
    findings = trivy.parse_report(json.dumps(REPORT))
    by_id = {f.rule_id: f for f in findings}
    assert len(findings) == 4
    assert by_id["CVE-2022-48174"].severity == Severity.CRITICAL
    assert by_id["CVE-2022-48174"].remediation == "Upgrade busybox to 1.1"
    assert by_id["CVE-2022-48174"].fix_available is True
    assert by_id["CVE-2023-0001"].remediation == "No fixed version available yet"
    assert by_id["CVE-2023-0001"].fix_available is False
    assert by_id["CVE-2023-0002"].severity == Severity.INFO
    assert len(by_id["CVE-2022-48174"].description) <= 500

    secret = by_id["secret:aws-access-key-id"]
    assert secret.location == "/app/.env:3"
    assert "AKIA" not in secret.model_dump_json()


def test_parse_empty_report() -> None:
    assert trivy.parse_report('{"SchemaVersion": 2, "ArtifactName": "scratch"}') == []


def _finding(rule_id: str, severity: Severity, fixable: bool = True) -> Finding:
    remediation = "Upgrade x" if fixable else "No fixed version available yet"
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        remediation=remediation,
        fix_available=fixable,
    )


def test_prioritize_orders_by_severity_then_fixability() -> None:
    ordered = prioritize(
        [
            _finding("low", Severity.LOW),
            _finding("crit-nofix", Severity.CRITICAL, fixable=False),
            _finding("crit-fix", Severity.CRITICAL),
            _finding("high", Severity.HIGH),
        ]
    )
    assert [f.rule_id for f in ordered] == ["crit-fix", "crit-nofix", "high", "low"]


def test_prioritize_truncates_with_marker() -> None:
    findings = [_finding(f"CVE-{i}", Severity.LOW) for i in range(10)]
    findings.append(_finding("CVE-critical", Severity.CRITICAL))
    result = prioritize(findings, limit=5)
    assert len(result) == 5
    assert result[0].rule_id == "CVE-critical"
    assert result[-1].rule_id == "SF-TRUNCATED"
    assert "7 lower-severity" in result[-1].title


def _request(target: str, target_type: TargetType = TargetType.IMAGE) -> ScanRequested:
    return ScanRequested(
        scan_id=uuid4(), project_id=uuid4(), target_type=target_type, target=target
    )


async def test_ignores_other_target_types() -> None:
    assert await handle_request(_request("FROM x", TargetType.DOCKERFILE)) is None


async def test_missing_binary_fails_cleanly() -> None:
    result = await handle_request(_request("alpine:3"), trivy_binary="no-such-trivy")
    assert result is not None
    assert result.status == ScanStatus.FAILED
    assert result.error and "not found" in result.error


@pytest.mark.skipif(TRIVY is None, reason="trivy not installed")
async def test_flag_like_target_is_not_interpreted_as_option() -> None:
    assert TRIVY
    with tempfile.TemporaryDirectory() as cache:
        result = await handle_request(
            _request("--help"), trivy_binary=TRIVY, timeout=60, cache_dir=cache
        )
    assert result is not None
    assert result.status == ScanStatus.FAILED
