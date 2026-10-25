"""Network side of the API scan: one GET (following redirects) and one TLS handshake."""

import asyncio
import ssl
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from sentinelflow_api_scanner import __version__
from sentinelflow_api_scanner.ssrf import (
    DestinationPolicy,
    ProbeError,
    guarded_client,
    unverified_ssl_context,
)

USER_AGENT = f"SentinelFlow-Scanner/{__version__} (+https://github.com/jofezs/SentinelFlow)"
# A syntactically valid origin that cannot belong to anyone (.invalid is reserved, RFC 2606).
PROBE_ORIGIN = "https://cors-probe.sentinelflow.invalid"
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class TlsInfo:
    version: str | None
    not_after: datetime | None = None
    cert_error: str | None = None


@dataclass(frozen=True)
class ProbeResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: httpx.Headers
    redirects: list[str] = field(default_factory=list)
    tls: TlsInfo | None = None


async def probe_tls(host: str, port: int, policy: DestinationPolicy, timeout: float) -> TlsInfo:
    ip = await policy.resolve(host, port)  # same SSRF policy as the HTTP request

    async def handshake(ctx: ssl.SSLContext) -> tuple[str | None, dict[str, object]]:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout
        )
        try:
            ssl_object: ssl.SSLObject = writer.get_extra_info("ssl_object")
            return ssl_object.version(), dict(ssl_object.getpeercert() or {})
        finally:
            writer.close()

    try:
        version, cert = await handshake(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        # Still learn the protocol version so other checks can run.
        version, _ = await handshake(unverified_ssl_context())
        return TlsInfo(version=version, cert_error=exc.verify_message or str(exc))

    not_after = cert.get("notAfter")
    expiry = (
        datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
        if isinstance(not_after, str)
        else None
    )
    return TlsInfo(version=version, not_after=expiry)


async def probe(url: str, policy: DestinationPolicy, timeout: float = 10.0) -> ProbeResult:
    headers = {"User-Agent": USER_AGENT, "Origin": PROBE_ORIGIN, "Accept": "*/*"}
    try:
        async with (
            guarded_client(
                policy, timeout, follow_redirects=True, max_redirects=MAX_REDIRECTS, headers=headers
            ) as client,
            client.stream("GET", url) as response,  # stream: headers only, body never read
        ):
            result = ProbeResult(
                requested_url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                headers=response.headers,
                redirects=[str(r.url) for r in response.history],
            )
    except httpx.TooManyRedirects as exc:
        raise ProbeError(f"more than {MAX_REDIRECTS} redirects") from exc
    except httpx.HTTPError as exc:
        raise ProbeError(f"request failed: {type(exc).__name__}: {exc}") from exc

    final = urlsplit(result.final_url)
    if final.scheme == "https" and final.hostname:
        try:
            tls = await probe_tls(final.hostname, final.port or 443, policy, timeout)
        except (OSError, TimeoutError) as exc:
            raise ProbeError(f"TLS handshake failed: {exc}") from exc
        result = replace(result, tls=tls)
    return result
