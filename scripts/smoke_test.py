"""End-to-end smoke test against a running SentinelFlow stack.

Usage:
    SENTINELFLOW_ADMIN_TOKEN=... python scripts/smoke_test.py [--base-url http://localhost:8000]

Creates a project, submits a deliberately insecure Dockerfile, waits for the
scan to complete, and checks the expected findings came back.
"""

import argparse
import os
import sys
import time
import uuid
from pathlib import Path

import httpx

INSECURE_DOCKERFILE = """\
FROM ubuntu:latest
ENV DB_PASSWORD=hunter2
RUN curl -fsSL https://example.com/install.sh | sh
EXPOSE 22
CMD ["/start.sh"]
"""
EXPECTED_RULES = {"SF001", "SF002", "SF005", "SF008", "DL3007"}


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        client.get("/readyz").raise_for_status()

        project = client.post(
            "/v1/projects",
            json={"name": f"smoke-{uuid.uuid4().hex[:8]}"},
            headers={"Authorization": f"Bearer {_admin_token()}"},
        )
        project.raise_for_status()
        headers = {"X-API-Key": project.json()["api_key"]}

        scan = client.post(
            "/v1/scans",
            json={"target_type": "dockerfile", "target": INSECURE_DOCKERFILE},
            headers=headers,
        )
        scan.raise_for_status()
        scan_id = scan.json()["id"]
        print(f"submitted scan {scan_id}")

        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            body = client.get(f"/v1/scans/{scan_id}", headers=headers).json()
            if body["status"] in {"completed", "failed"}:
                break
            time.sleep(0.5)
        else:
            print(f"FAIL: scan still {body['status']} after {args.timeout}s")
            return 1

    if body["status"] != "completed":
        print(f"FAIL: scan {body['status']}: {body['error']}")
        return 1
    found = {f["rule_id"] for f in body["findings"]}
    print(f"status={body['status']} max_severity={body['max_severity']} findings={len(found)}")
    for f in body["findings"]:
        print(f"  [{f['severity']:>8}] {f['rule_id']:<7} {f['location'] or '':<8} {f['title']}")
    missing = EXPECTED_RULES - found
    if missing:
        print(f"FAIL: expected rules not reported: {sorted(missing)}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
