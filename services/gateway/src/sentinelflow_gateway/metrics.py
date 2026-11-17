"""Gateway business metrics (Prometheus). Compliance is derived from these, e.g.

pass rate = sum(rate(sentinelflow_policy_decisions_total{result="passed"}[1h]))
          / sum(rate(sentinelflow_policy_decisions_total[1h]))
"""

from prometheus_client import Counter, Histogram

from sentinelflow_common.events import ScanStatus, Severity, TargetType
from sentinelflow_common.policies import POLICIES

HTTP_REQUESTS = Counter(
    "sentinelflow_http_requests_total",
    "API requests by route template, method, and status code",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "sentinelflow_http_request_duration_seconds",
    "API request latency by route template",
    ["method", "route"],
)
SCANS_SUBMITTED = Counter(
    "sentinelflow_scans_submitted_total", "Scans accepted by the API", ["target_type"]
)
SCAN_RESULTS = Counter(
    "sentinelflow_scan_results_total", "Scan results recorded", ["target_type", "status"]
)
FINDINGS = Counter("sentinelflow_findings_total", "Findings recorded", ["target_type", "severity"])
POLICY_DECISIONS = Counter(
    "sentinelflow_policy_decisions_total", "Policy decisions recorded", ["target_type", "result"]
)
POLICY_VIOLATIONS = Counter(
    "sentinelflow_policy_violations_total", "Policy violations recorded", ["policy_id"]
)
OUTBOX_RELAYED = Counter("sentinelflow_outbox_relayed_total", "Outbox events published")
WEBHOOK_DELIVERIES = Counter(
    "sentinelflow_webhook_deliveries_total",
    "Webhook delivery attempts by outcome (delivered, retry, failed)",
    ["outcome"],
)
WEBHOOK_LATENCY = Histogram(
    "sentinelflow_webhook_request_duration_seconds", "Webhook HTTP request latency"
)


def _initialize_label_sets() -> None:
    """Export every known label combination at 0 from process start.

    A labelled counter otherwise appears only on its first increment (already
    at 1), so increase()/rate() miss that first event entirely - which matters
    most for rare, important events like the first policy failure.
    """
    for target_type in TargetType:
        SCANS_SUBMITTED.labels(target_type.value)
        for status in ScanStatus:
            SCAN_RESULTS.labels(target_type.value, status.value)
        for severity in Severity:
            FINDINGS.labels(target_type.value, severity.value)
        for result in ("passed", "failed"):
            POLICY_DECISIONS.labels(target_type.value, result)
    for policy_id in POLICIES:
        POLICY_VIOLATIONS.labels(policy_id)
    for outcome in ("delivered", "retry", "failed"):
        WEBHOOK_DELIVERIES.labels(outcome)


_initialize_label_sets()
