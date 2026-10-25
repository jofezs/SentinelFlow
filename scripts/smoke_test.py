"""End-to-end smoke test against a running SentinelFlow stack.

Usage:
    SENTINELFLOW_ADMIN_TOKEN=... python scripts/smoke_test.py [--base-url http://localhost:8000]

Creates a project, submits one scan of each target type (plus an SSRF attempt),
waits for them to finish, and checks the results.
"""

import argparse
import os
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

INSECURE_DOCKERFILE = """\
FROM ubuntu:latest
ENV DB_PASSWORD=hunter2
RUN curl -fsSL https://example.com/install.sh | sh
EXPOSE 22
CMD ["/start.sh"]
"""

HARDENED_DOCKERFILE = """\
FROM python:3.12-slim
USER 10001
HEALTHCHECK CMD ["python", "-c", "print('ok')"]
CMD ["python", "-m", "http.server"]
"""

Scan = dict[str, Any]


def _rules(scan: Scan) -> set[str]:
    return {f["rule_id"] for f in scan["findings"]}


@dataclass
class Case:
    name: str
    target_type: str
    target: str
    check: Callable[[Scan], str | None]  # returns an error message, or None if OK
    policy_passed: bool | None = None  # expected decision (None: no evaluation expected)
    violated: frozenset[str] = frozenset()  # policies that must appear in the violations

    def check_policy(self, scan: Scan) -> str | None:
        if scan["policy_passed"] is not self.policy_passed:
            return f"expected policy_passed={self.policy_passed}, got {scan['policy_passed']}"
        missing = self.violated - {v["policy_id"] for v in scan["policy_violations"]}
        return f"expected policy violations {sorted(missing)}" if missing else None


def _expect_rules(*rules: str) -> Callable[[Scan], str | None]:
    def check(scan: Scan) -> str | None:
        if scan["status"] != "completed":
            return f"status {scan['status']}: {scan['error']}"
        missing = set(rules) - _rules(scan)
        return f"missing rules {sorted(missing)}" if missing else None

    return check


def _expect_cves(scan: Scan) -> str | None:
    if scan["status"] != "completed":
        return f"status {scan['status']}: {scan['error']}"
    if not any(r.startswith("CVE-") for r in _rules(scan)):
        return "no CVEs reported for a known-vulnerable image"
    return None


def _expect_completed(scan: Scan) -> str | None:
    return None if scan["status"] == "completed" else f"status {scan['status']}: {scan['error']}"


def _expect_blocked(scan: Scan) -> str | None:
    if scan["status"] == "failed" and "not allowed" in (scan["error"] or ""):
        return None
    return f"SSRF target was not blocked (status {scan['status']}, error {scan['error']!r})"


CASES = [
    Case(
        "dockerfile", "dockerfile", INSECURE_DOCKERFILE,
        _expect_rules("SF001", "SF002", "SF005", "SF008", "DL3007"),
        policy_passed=False,
        violated=frozenset(
            {"severity_threshold", "no_secrets", "no_root_container", "supply_chain"}
        ),
    ),
    Case("hardened", "dockerfile", HARDENED_DOCKERFILE, _expect_completed, policy_passed=True),
    Case(
        "image", "image", "alpine:3.18.0", _expect_cves,
        policy_passed=False, violated=frozenset({"severity_threshold", "no_fixable_vulns"}),
    ),
    Case(
        "api", "api_endpoint", "https://example.com/", _expect_completed,
        policy_passed=False, violated=frozenset({"hsts_required"}),
    ),
    Case("ssrf", "api_endpoint", "http://169.254.169.254/latest/meta-data/", _expect_blocked),
]  # fmt: skip


def _finished(scan: Scan) -> bool:
    """Failed scans are final; completed scans are final once the policy decision is in."""
    return scan["status"] == "failed" or (
        scan["status"] == "completed" and scan["policy_passed"] is not None
    )


def _admin_token() -> str:
    token = os.environ.get("SENTINELFLOW_ADMIN_TOKEN")
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not token and env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("SENTINELFLOW_ADMIN_TOKEN="):
                token = line.split("=", 1)[1].strip()
    if not token:
        sys.exit("SENTINELFLOW_ADMIN_TOKEN is not set")
    return token


def _print_scan(name: str, scan: Scan) -> None:
    print(
        f"\n[{name}] {scan['target'][:60]!r} -> {scan['status']} "
        f"(max={scan['max_severity']}, findings={scan['finding_count']}) {scan['error'] or ''}"
    )
    for f in scan["findings"][:4]:
        print(f"  [{f['severity']:>8}] {f['rule_id']:<16} {f['title'][:70]}")
    if scan["finding_count"] > 4:
        print(f"  ... and {scan['finding_count'] - 4} more")
    if scan["policy_passed"] is not None:
        print(f"  policy: {'PASSED' if scan['policy_passed'] else 'FAILED'}")
        for v in scan["policy_violations"]:
            print(f"    x {v['policy_id']:<20} [{v['severity']}] {v['message'][:70]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--only", nargs="*", help="run only these cases")
    args = parser.parse_args()
    cases = [c for c in CASES if not args.only or c.name in args.only]

    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        client.get("/readyz").raise_for_status()
        project = client.post(
            "/v1/projects",
            json={"name": f"smoke-{uuid.uuid4().hex[:8]}"},
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )
        project.raise_for_status()
        headers = {"X-API-Key": project.json()["api_key"]}

        pending: dict[str, Case] = {}
        for case in cases:
            resp = client.post(
                "/v1/scans",
                json={"target_type": case.target_type, "target": case.target},
                headers=headers,
            )
            resp.raise_for_status()
            pending[resp.json()["id"]] = case

        results: dict[str, Scan] = {}
        deadline = time.monotonic() + args.timeout
        while pending and time.monotonic() < deadline:
            for scan_id in list(pending):
                scan = client.get(f"/v1/scans/{scan_id}", headers=headers).json()
                if _finished(scan):
                    results[pending.pop(scan_id).name] = scan
            time.sleep(1)

    failures = [f"{case.name}: timed out" for case in pending.values()]
    for case in cases:
        if case.name in results:
            _print_scan(case.name, results[case.name])
            for error in (case.check(results[case.name]), case.check_policy(results[case.name])):
                if error:
                    failures.append(f"{case.name}: {error}")

    print()
    for failure in failures:
        print(f"FAIL {failure}")
    print("PASS" if not failures else f"{len(failures)} case(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
