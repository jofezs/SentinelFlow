"""Example SentinelFlow webhook receiver (development and e2e testing).

Standard library only, so it doubles as a reference for integrators:

    POST /hook      records the delivery; if WEBHOOK_SECRET is set, verifies the
                    signature first and answers 401 when it does not match
    GET  /received  recorded deliveries as JSON (most recent last)
    GET  /healthz   liveness

Verifying a delivery:
  1. Parse X-SentinelFlow-Signature: "t=<unix ts>,v1=<hex>"
  2. Reject if |now - t| > 300s (replay protection)
  3. expected = HMAC-SHA256(secret, f"{t}." + raw_body), compare in constant time
  4. De-duplicate on X-SentinelFlow-Delivery (delivery is at-least-once)
"""

import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("WEBHOOK_SECRET", "")
TOLERANCE_SECONDS = 300
MAX_BODY_BYTES = 1_000_000
received: list[dict[str, object]] = []


def verify(secret: str, header: str, body: bytes) -> bool:
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
    except (KeyError, ValueError):
        return False
    if abs(time.time() - timestamp) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), parts.get("v1", ""))


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/received":
            self._json(200, received)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != "/hook" or length > MAX_BODY_BYTES:
            self._json(404 if self.path != "/hook" else 413, {"error": "rejected"})
            return
        body = self.rfile.read(length)
        signature = self.headers.get("X-SentinelFlow-Signature", "")
        verified = verify(SECRET, signature, body) if SECRET else None
        if verified is False:
            self._json(401, {"error": "invalid signature"})
            return
        received.append(
            {
                "delivery": self.headers.get("X-SentinelFlow-Delivery"),
                "event": self.headers.get("X-SentinelFlow-Event"),
                "signature": signature,
                "verified": verified,
                "body": body.decode(errors="replace"),
            }
        )
        del received[:-200]  # keep memory bounded
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"receiver: {fmt % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"webhook receiver listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()  # noqa: S104
