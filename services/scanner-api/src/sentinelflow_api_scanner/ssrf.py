"""SSRF protection for outbound probes.

Validating a URL up front is not enough: DNS can return a different (internal)
address by the time we connect ("DNS rebinding"), and redirects can point
anywhere. Instead, the check lives in the network layer. Every TCP connection,
including those made while following redirects, goes through
``DestinationPolicy.resolve``, and we connect to exactly the IP that was
validated, never re-resolving the hostname. TLS SNI and the Host header still
use the original hostname.
"""

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatch

import httpcore
import httpx

DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})


class ProbeError(Exception):
    """The target could not be probed (resolution, connection, protocol)."""


class BlockedDestination(ProbeError):
    """The target is not an allowed destination (SSRF protection)."""


@dataclass(frozen=True)
class DestinationPolicy:
    allowed_ports: frozenset[int] | None = DEFAULT_ALLOWED_PORTS  # None = any port
    allowed_hosts: tuple[str, ...] = ()  # fnmatch patterns; empty = any public host
    allow_private: bool = False  # tests only: permits loopback/private targets

    def check_host(self, host: str) -> None:
        host = host.lower().rstrip(".")
        if self.allowed_hosts and not any(fnmatch(host, p.lower()) for p in self.allowed_hosts):
            raise BlockedDestination(f"host {host!r} is not in the allowlist")

    def check_ip(self, address: str) -> None:
        ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop IPv6 zone id
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback in disguise
        if self.allow_private:
            return
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise BlockedDestination(f"{ip} is not a public address")

    async def resolve(self, host: str, port: int) -> str:
        """Return a validated IP to connect to, or raise BlockedDestination."""
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise BlockedDestination(f"port {port} is not allowed")
        self.check_host(host)
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ProbeError(f"could not resolve {host!r}") from exc
        addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
        if not addresses:
            raise ProbeError(f"no addresses for {host!r}")
        # Every answer must be public: a mixed answer could still route internally.
        for address in addresses:
            self.check_ip(address)
        return addresses[0]


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that routes every connection through the policy."""

    def __init__(self, policy: DestinationPolicy) -> None:
        self._policy = policy
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        ip = await self._policy.resolve(host, port)
        return await self._inner.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise BlockedDestination("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def unverified_ssl_context() -> ssl.SSLContext:
    """For reading headers only; certificate validity is assessed separately."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class GuardedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, policy: DestinationPolicy) -> None:
        super().__init__(retries=0)
        # httpx does not expose a network-backend option, so replace its pool with
        # one whose backend enforces the destination policy on every connection.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=unverified_ssl_context(),
            network_backend=GuardedBackend(policy),
        )


def guarded_client(
    policy: DestinationPolicy, timeout: float, **kwargs: object
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=GuardedTransport(policy),
        timeout=timeout,
        trust_env=False,  # never route through env-configured proxies (would bypass the guard)
        **kwargs,  # type: ignore[arg-type]
    )
