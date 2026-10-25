import json
import shutil
from uuid import uuid4

import pytest

from sentinelflow_common.events import ScanRequested, ScanStatus, Severity, TargetType
from sentinelflow_dockerfile_scanner import hadolint
from sentinelflow_dockerfile_scanner.scanner import handle_request

HADOLINT = shutil.which("hadolint")
needs_hadolint = pytest.mark.skipif(HADOLINT is None, reason="hadolint not installed")


def _request(target: str, target_type: TargetType = TargetType.DOCKERFILE) -> ScanRequested:
    return ScanRequested(
        scan_id=uuid4(), project_id=uuid4(), target_type=target_type, target=target
    )


def test_parse_hadolint_output() -> None:
    raw = json.dumps(
        [
            {"code": "DL3007", "level": "warning", "line": 1, "message": "Using latest"},
            {"code": "SC2086", "level": "info", "line": 3, "message": "Quote vars"},
            {"code": "DL9999", "level": "unknown", "line": 2, "message": "?"},
        ]
    )
    findings = hadolint.parse_output(raw)
    assert [(f.rule_id, f.severity, f.location) for f in findings] == [
        ("DL3007", Severity.MEDIUM, "line 1"),
        ("SC2086", Severity.LOW, "line 3"),
        ("DL9999", Severity.INFO, "line 2"),
    ]
    assert findings[0].remediation and "hadolint/wiki/DL3007" in findings[0].remediation
    assert findings[1].remediation and "shellcheck.net" in findings[1].remediation
    assert hadolint.parse_output("") == []


async def test_ignores_non_dockerfile_requests() -> None:
    assert await handle_request(_request("nginx", TargetType.IMAGE)) is None


async def test_missing_binary_produces_failed_result() -> None:
    result = await handle_request(_request("FROM alpine"), hadolint_binary="no-such-hadolint")
    assert result is not None
    assert result.status == ScanStatus.FAILED
    assert result.error and "not found" in result.error
    assert result.findings == ()


@needs_hadolint
async def test_end_to_end_with_real_hadolint() -> None:
    assert HADOLINT
    content = "FROM ubuntu:latest\nENV API_KEY=abc\nRUN curl https://x.sh | sh\n"
    result = await handle_request(_request(content), hadolint_binary=HADOLINT)
    assert result is not None
    assert result.status == ScanStatus.SUCCEEDED
    ids = [f.rule_id for f in result.findings]
    assert {"SF001", "SF002", "SF005", "DL3007"} <= set(ids)
    # Sorted by severity: the critical secret comes first.
    assert result.findings[0].rule_id == "SF002"
    assert result.max_severity() == Severity.CRITICAL
