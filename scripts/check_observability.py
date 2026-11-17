"""Check the observability stack after the smoke test has generated traffic.

- every SentinelFlow service is scraped by Prometheus and "up"
- the business metrics the dashboard relies on have data
- Grafana has provisioned the compliance dashboard
"""

import argparse
import sys
import time

import httpx

REQUIRED_SERIES = [
    "sentinelflow_scans_submitted_total",
    "sentinelflow_scan_results_total",
    "sentinelflow_policy_decisions_total",
    "sentinelflow_webhook_deliveries_total",
    "sentinelflow_scanner_duration_seconds_count",
    "sentinelflow_policy_evaluation_duration_seconds_count",
    "sentinelflow_http_requests_total",
]


def has_data(client: httpx.Client, prometheus: str, series: str) -> bool:
    resp = client.get(f"{prometheus}/api/v1/query", params={"query": series})
    return bool(resp.json()["data"]["result"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--grafana", default="http://127.0.0.1:3000")
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()
    failures: list[str] = []

    with httpx.Client(timeout=10) as client:
        deadline = time.monotonic() + args.timeout
        while True:  # wait for at least one scrape after the smoke test's traffic
            targets = client.get(f"{args.prometheus}/api/v1/targets").json()["data"]
            ours = [t for t in targets["activeTargets"] if t["labels"]["job"] == "sentinelflow"]
            down = [t["labels"]["service"] for t in ours if t["health"] != "up"]
            missing = [s for s in REQUIRED_SERIES if not has_data(client, args.prometheus, s)]
            if (not down and not missing) or time.monotonic() > deadline:
                break
            time.sleep(3)

        print(f"prometheus targets up: {len(ours) - len(down)}/{len(ours)}")
        failures += [f"target down: {s}" for s in down]
        failures += [f"no data for {m}" for m in missing]

        dashboards = client.get(
            f"{args.grafana}/api/search", params={"query": "SentinelFlow Compliance"}
        ).json()
        if not any(d.get("uid") == "sentinelflow-compliance" for d in dashboards):
            failures.append("grafana dashboard not provisioned")
        else:
            print("grafana dashboard provisioned: SentinelFlow Compliance")

    for failure in failures:
        print(f"FAIL {failure}")
    print("PASS" if not failures else f"{len(failures)} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
