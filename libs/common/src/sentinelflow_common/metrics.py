"""Prometheus metrics shared by every service.

Workers expose them with ``serve_metrics(port)``; the gateway API serves them
at /metrics. Naming follows Prometheus conventions (``_total`` counters,
``_seconds`` histograms, base units).
"""

from prometheus_client import Counter, Histogram, start_http_server

MESSAGES = Counter(
    "sentinelflow_messages_total",
    "Bus messages handled, by consumer and outcome (ack, nak = retried, term = dropped)",
    ["consumer", "outcome"],
)

SCANS = Counter(
    "sentinelflow_scanner_scans_total",
    "Scans processed by each scanner, by result status",
    ["scanner", "status"],
)

SCAN_DURATION = Histogram(
    "sentinelflow_scanner_duration_seconds",
    "Time taken to scan one target",
    ["scanner"],
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)


def serve_metrics(port: int) -> None:
    """Expose /metrics on ``port`` from a background thread (0 disables it)."""
    if port:
        start_http_server(port)
