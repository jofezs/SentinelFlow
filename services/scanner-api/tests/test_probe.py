"""Probe tests against a local HTTP server (loopback is only reachable with allow_private)."""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

from sentinelflow_api_scanner.probe import PROBE_ORIGIN, USER_AGENT, probe
from sentinelflow_api_scanner.scanner import handle_request
from sentinelflow_api_scanner.ssrf import BlockedDestination, DestinationPolicy
from sentinelflow_common.events import ScanRequested, ScanStatus, TargetType

LOCAL = DestinationPolicy(allowed_ports=None, allow_private=True)
seen_headers: dict[str, str] = {}


class Handler(BaseHTTPRequestHandler):
    def version_string(self) -> str:  # sent as the Server header
        return "TestServer/1.2.3"

    def do_GET(self) -> None:
        seen_headers.update({k.lower(): v for k, v in self.headers.items()})
        port = self.server.server_address[1]
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/insecure")
        elif self.path == "/redirect-elsewhere":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/insecure")
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "session=s3cr3t; Path=/")
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


async def test_probe_collects_headers_and_follows_redirects(server: str) -> None:
    result = await probe(f"{server}/redirect", LOCAL)
    assert result.status_code == 200
    assert result.final_url == f"{server}/insecure"
    assert result.redirects == [f"{server}/redirect"]
    assert result.headers["server"] == "TestServer/1.2.3"
    assert result.tls is None
    # The probe identifies itself and sends the CORS probe origin.
    assert seen_headers["user-agent"] == USER_AGENT
    assert seen_headers["origin"] == PROBE_ORIGIN


async def test_scan_reports_expected_findings(server: str) -> None:
    event = ScanRequested(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.API_ENDPOINT,
        target=f"{server}/insecure",
    )
    result = await handle_request(event, policy=LOCAL)
    assert result is not None
    assert result.status == ScanStatus.SUCCEEDED
    ids = [f.rule_id for f in result.findings]
    assert {"API001", "API015", "API016", "API020"} <= set(ids)
    assert ids[0] == "API020"  # CORS reflection with credentials is critical -> first
    assert "s3cr3t" not in result.model_dump_json()


async def test_default_policy_blocks_loopback(server: str) -> None:
    with pytest.raises(BlockedDestination):
        await probe(f"{server}/insecure", DestinationPolicy(allowed_ports=None))


async def test_redirects_are_checked_by_the_guard(server: str) -> None:
    # Allowed start host; the redirect goes to a host outside the allowlist.
    policy = DestinationPolicy(allowed_ports=None, allowed_hosts=("127.0.0.1",), allow_private=True)
    assert (await probe(f"{server}/redirect", policy)).status_code == 200
    with pytest.raises(BlockedDestination, match="localhost"):
        await probe(f"{server}/redirect-elsewhere", policy)


async def test_blocked_destination_becomes_failed_scan(server: str) -> None:
    event = ScanRequested(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.API_ENDPOINT,
        target="http://169.254.169.254/latest/meta-data/",
    )
    result = await handle_request(event)
    assert result is not None
    assert result.status == ScanStatus.FAILED
    assert result.error and result.error.startswith("destination not allowed")


async def test_redirect_loop_fails_cleanly(server: str) -> None:
    event = ScanRequested(
        scan_id=uuid4(),
        project_id=uuid4(),
        target_type=TargetType.API_ENDPOINT,
        target=f"{server}/loop",
    )
    result = await handle_request(event, policy=LOCAL)
    assert result is not None
    assert result.status == ScanStatus.FAILED
    assert result.error and "redirects" in result.error
