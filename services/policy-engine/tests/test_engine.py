import json
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from sentinelflow_common.events import (
    Finding,
    PolicyConfig,
    PolicyEvaluationRequested,
    Severity,
    TargetType,
)
from sentinelflow_common.policies import POLICIES
from sentinelflow_policy_engine.engine import build_input, evaluate, to_event
from sentinelflow_policy_engine.opa import DECISION_PATH, OpaClient, OpaError

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
OPA_URL = os.environ.get("SENTINELFLOW_TEST_OPA_URL")


def _request(**overrides: Any) -> PolicyEvaluationRequested:
    fields: dict[str, Any] = {
        "scan_id": uuid4(),
        "project_id": uuid4(),
        "target_type": TargetType.DOCKERFILE,
        "target": "FROM alpine",
        "scanner": "dockerfile:hadolint+sf-rules",
        "findings": (
            Finding(rule_id="SF001", title="root", severity=Severity.HIGH, location="line 1"),
        ),
    }
    fields.update(overrides)
    return PolicyEvaluationRequested.model_validate(fields)


def test_rego_policies_match_catalog() -> None:
    """Every catalog entry has a Rego package and vice versa."""
    packages = set()
    for path in (POLICY_DIR / "policies").glob("*.rego"):
        match = re.search(r"^package sentinelflow\.policies\.(\w+)$", path.read_text(), re.M)
        assert match, f"{path.name} has no sentinelflow.policies package"
        packages.add(match.group(1))
    assert packages == set(POLICIES)


def test_build_input_shape() -> None:
    request = _request(config=PolicyConfig(enabled=("no_root_container",)))
    doc = build_input(request)
    assert doc["scan"] == {
        "target_type": "dockerfile",
        "target": "FROM alpine",
        "scanner": "dockerfile:hadolint+sf-rules",
    }
    assert doc["findings"][0]["rule_id"] == "SF001"
    assert doc["config"] == {"enabled": ["no_root_container"], "params": {}}
    json.dumps(doc)  # must be JSON-serializable


def test_to_event_sorts_violations_by_severity() -> None:
    result = {
        "allow": False,
        "violations": [
            {"policy_id": "hsts_required", "message": "m", "severity": "medium"},
            {"policy_id": "no_secrets", "message": "m", "severity": "critical"},
        ],
    }
    event = to_event(_request(), result)
    assert not event.passed
    assert [v.policy_id for v in event.violations] == ["no_secrets", "hsts_required"]


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"allow": "yes"},
        {"allow": True, "violations": [{"policy_id": "x", "message": "m", "severity": "low"}]},
        {"allow": False, "violations": [{"policy_id": "x", "message": "m", "severity": "bad"}]},
    ],
)
def test_malformed_decisions_are_rejected(result: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        to_event(_request(), result)


def _opa(handler: Any) -> OpaClient:
    return OpaClient("http://opa", transport=httpx.MockTransport(handler))


async def test_client_posts_input_and_returns_result() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"result": {"allow": True, "violations": []}})

    event = await evaluate(_opa(handler), _request())
    assert event.passed
    assert seen["path"] == DECISION_PATH
    assert seen["body"]["input"]["scan"]["target_type"] == "dockerfile"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={}),  # undefined decision: policies not loaded
        httpx.Response(500, json={"code": "internal_error"}),
    ],
)
async def test_client_fails_closed(response: httpx.Response) -> None:
    with pytest.raises(OpaError):
        await evaluate(_opa(lambda _: response), _request())


async def test_wait_ready_gives_up() -> None:
    client = _opa(lambda _: httpx.Response(503))
    with pytest.raises(OpaError, match="did not become ready"):
        await client.wait_ready(attempts=2, delay=0)


@pytest.mark.skipif(not OPA_URL, reason="SENTINELFLOW_TEST_OPA_URL not set")
async def test_against_real_opa() -> None:
    assert OPA_URL
    client = OpaClient(OPA_URL)
    await client.wait_ready(attempts=5)
    denied = await evaluate(client, _request())
    allowed = await evaluate(client, _request(findings=()))
    disabled = await evaluate(client, _request(config=PolicyConfig(enabled=("supply_chain",))))
    await client.close()

    assert not denied.passed
    assert [v.policy_id for v in denied.violations] == ["no_root_container"]
    assert denied.violations[0].message == "Container runs as root: SF001 (line 1)"
    assert allowed.passed
    assert disabled.passed
