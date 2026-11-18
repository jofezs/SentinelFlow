"""Narrated walkthrough of SentinelFlow for the README demo (recorded with VHS).

Standard library only, so it runs anywhere Python does:

    SENTINELFLOW_ADMIN_TOKEN=... python scripts/demo.py [--base-url ...] [--receiver-url ...]

Creates a project, subscribes a webhook, scans an insecure Dockerfile, shows the findings and
the policy decision, verifies the signed webhook alert, and attempts an SSRF that is refused.
"""

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.request
import uuid
from typing import Any

INSECURE_DOCKERFILE = """\
FROM ubuntu:latest
ENV DB_PASSWORD=hunter2
RUN curl -fsSL https://example.com/install.sh | sh
EXPOSE 22
CMD ["/start.sh"]
"""

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
RED, GREEN, YELLOW, CYAN, MAGENTA = (f"\033[{c}m" for c in (31, 32, 33, 36, 35))
SEVERITY = {"critical": MAGENTA, "high": RED, "medium": YELLOW, "low": CYAN, "info": DIM}


def call(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None) -> Any:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"refusing non-HTTP URL: {url}")
    data = json.dumps(body).encode() if body is not None else None
    # Scheme checked above, so urllib can't be steered to file:// or custom handlers.
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})  # noqa: S310
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        raw = response.read()
    return json.loads(raw) if raw else None


def step(text: str) -> None:
    print(f"\n{BOLD}{CYAN}▶ {text}{RESET}")
    time.sleep(0.6)


def wait_for(api: str, scan_id: str, headers: dict[str, str]) -> dict[str, Any]:
    print(f"  {DIM}scanning", end="", flush=True)
    while True:
        scan: dict[str, Any] = call("GET", f"{api}/v1/scans/{scan_id}", headers=headers)
        if scan["status"] == "failed" or (
            scan["status"] == "completed" and scan["policy_passed"] is not None
        ):
            print(f" done{RESET}")
            return scan
        print(".", end="", flush=True)
        time.sleep(0.5)


def signature_valid(secret: str, header: str, body: bytes) -> bool:
    parts = dict(item.split("=", 1) for item in header.split(","))
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), parts.get("v1", ""))


def main() -> None:
    parser = argparse.ArgumentParser()
    env = os.environ.get
    parser.add_argument("--base-url", default=env("SENTINELFLOW_URL", "http://127.0.0.1:8000"))
    parser.add_argument(
        "--receiver-url", default=env("SENTINELFLOW_RECEIVER_URL", "http://127.0.0.1:8090")
    )
    parser.add_argument("--webhook-url", default="http://webhook-receiver:8080/hook")
    args = parser.parse_args()
    api, admin = args.base_url, os.environ["SENTINELFLOW_ADMIN_TOKEN"]

    step("Create a project (admin) and subscribe a webhook to policy failures")
    project = call(
        "POST",
        f"{api}/v1/projects",
        {"name": f"demo-{uuid.uuid4().hex[:6]}"},
        {"Authorization": f"Bearer {admin}"},
    )
    headers = {"X-API-Key": project["api_key"]}
    hook = call(
        "PUT",
        f"{api}/v1/projects/me/webhook",
        {"url": args.webhook_url, "events": ["policy.failed"]},
        headers,
    )
    print(f"  project {BOLD}{project['name']}{RESET}  API key {project['api_key'][:10]}…")
    print(f"  webhook → {hook['url']}  {DIM}(HMAC-signed){RESET}")

    step("Submit an insecure Dockerfile")
    for line in INSECURE_DOCKERFILE.splitlines():
        print(f"  {DIM}│{RESET} {line}")
    scan_id = call(
        "POST",
        f"{api}/v1/scans",
        {"target_type": "dockerfile", "target": INSECURE_DOCKERFILE},
        headers,
    )["id"]
    scan = wait_for(api, scan_id, headers)

    step(f"Findings: {len(scan['findings'])}")
    for f in scan["findings"][:6]:
        colour = SEVERITY.get(f["severity"], "")
        print(f"  {colour}{f['severity']:>8}{RESET}  {f['rule_id']:<7} {f['title'][:62]}")

    step("Policy decision (OPA / Rego)")
    verdict = f"{GREEN}PASSED" if scan["policy_passed"] else f"{RED}FAILED"
    print(f"  {BOLD}{verdict}{RESET}")
    for v in scan["policy_violations"]:
        print(f"  {RED}✗{RESET} {v['policy_id']:<19} {v['message'][:72]}")

    step("Signed webhook alert received")
    delivery = None
    for _ in range(60):
        delivery = next(
            (
                d
                for d in reversed(call("GET", f"{args.receiver_url}/received"))
                if json.loads(d["body"])["project"]["id"] == project["id"]
            ),
            None,
        )
        if delivery:
            break
        time.sleep(0.5)
    if delivery is None:
        raise SystemExit("no webhook delivery received within 30s")
    ok = signature_valid(hook["secret"], delivery["signature"], delivery["body"].encode())
    print(f"  event {BOLD}{delivery['event']}{RESET}  delivery {delivery['delivery'][:8]}…")
    print(f"  signature {GREEN + 'valid ✓' if ok else RED + 'INVALID'}{RESET}")

    step("Try to make the API scanner fetch cloud credentials (SSRF)")
    target = "http://169.254.169.254/latest/meta-data/"
    print(f"  target {target}")
    scan_id = call(
        "POST", f"{api}/v1/scans", {"target_type": "api_endpoint", "target": target}, headers
    )["id"]
    scan = wait_for(api, scan_id, headers)
    print(f"  {GREEN}refused ✓{RESET}  {scan['error']}")
    print()


if __name__ == "__main__":
    main()
