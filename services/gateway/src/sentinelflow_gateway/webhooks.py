"""Webhook payloads and signatures.

Signature scheme (same shape as Stripe's), sent as ``X-SentinelFlow-Signature``::

    t=<unix timestamp>,v1=<hex HMAC-SHA256(secret, f"{t}.{raw body}")>

Receivers recompute the HMAC over the *raw* body, compare in constant time, and
reject timestamps older than a few minutes (replay protection). Each delivery
also carries a unique ``X-SentinelFlow-Delivery`` id for de-duplication, since
delivery is at-least-once.
"""

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelflow_gateway.models import Project, Scan, WebhookDelivery, utcnow

SECRET_PREFIX = "whsec_"  # noqa: S105 - a public prefix, not a credential
EVENT_TYPES = frozenset({"policy.failed", "policy.passed", "scan.failed"})
DEFAULT_EVENTS = ("policy.failed",)
SIGNATURE_TOLERANCE_SECONDS = 300


def generate_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def verify(
    secret: str,
    header: str,
    body: bytes,
    now: float | None = None,
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
) -> bool:
    """Reference verifier (receivers should implement the same logic)."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        received = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - timestamp) > tolerance:
        return False
    expected = sign(secret, timestamp, body).split("v1=", 1)[1]
    return hmac.compare_digest(expected, received)


def _scan_summary(scan: Scan) -> dict[str, Any]:
    target = scan.target if len(scan.target) <= 200 else scan.target[:197] + "..."
    return {
        "id": str(scan.id),
        "target_type": scan.target_type.value,
        "target": target,
        "status": scan.status.value,
        "max_severity": scan.max_severity.value if scan.max_severity else None,
        "finding_count": scan.finding_count,
        "policy_passed": scan.policy_passed,
    }


def build_payload(
    delivery_id: uuid.UUID, event_type: str, project: Project, data: dict[str, Any]
) -> str:
    return json.dumps(
        {
            "id": str(delivery_id),
            "type": event_type,
            "created_at": utcnow().isoformat(),
            "project": {"id": str(project.id), "name": project.name},
            "data": data,
        },
        separators=(",", ":"),
    )


def subscribed(project: Project, event_type: str) -> bool:
    if not project.webhook_url:
        return False
    return event_type == "ping" or event_type in (project.webhook_events or DEFAULT_EVENTS)


def enqueue(
    session: AsyncSession, project: Project, event_type: str, data: dict[str, Any]
) -> WebhookDelivery | None:
    """Queue a delivery in the caller's transaction (if the project subscribes)."""
    if not subscribed(project, event_type):
        return None
    delivery_id = uuid.uuid4()
    delivery = WebhookDelivery(
        id=delivery_id,
        project_id=project.id,
        event_type=event_type,
        payload=build_payload(delivery_id, event_type, project, data),
    )
    session.add(delivery)
    return delivery


def enqueue_for_scan(
    session: AsyncSession, project: Project, scan: Scan, event_type: str
) -> WebhookDelivery | None:
    data: dict[str, Any] = {"scan": _scan_summary(scan)}
    if event_type.startswith("policy."):
        data["violations"] = scan.policy_violations or []
    if event_type == "scan.failed":
        data["error"] = scan.error
    return enqueue(session, project, event_type, data)
