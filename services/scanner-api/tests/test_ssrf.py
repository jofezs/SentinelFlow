import pytest

from sentinelflow_api_scanner.ssrf import BlockedDestination, DestinationPolicy, ProbeError

POLICY = DestinationPolicy()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # RFC 1918
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata endpoint (link-local)
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",  # noqa: S104  unspecified
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "::1",
        "fe80::1",
        "fc00::1",  # unique local
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",
    ],
)
def test_non_public_addresses_blocked(address: str) -> None:
    with pytest.raises(BlockedDestination):
        POLICY.check_ip(address)


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(address: str) -> None:
    POLICY.check_ip(address)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "2130706433",  # decimal encoding of 127.0.0.1
        "0x7f000001",  # hex encoding of 127.0.0.1
        "127.1",  # short form
    ],
)
async def test_hostnames_resolving_to_loopback_are_refused(host: str) -> None:
    # glibc (the container runtime) resolves the legacy numeric forms to 127.0.0.1 and
    # they are blocked; Windows' resolver rejects them outright. Either way: no request.
    with pytest.raises(ProbeError):
        await POLICY.resolve(host, 80)


async def test_disallowed_port_blocked_before_resolution() -> None:
    with pytest.raises(BlockedDestination, match="port 22"):
        await POLICY.resolve("example.com", 22)


async def test_host_allowlist() -> None:
    policy = DestinationPolicy(allowed_hosts=("*.example.com",), allow_private=True)
    with pytest.raises(BlockedDestination, match="allowlist"):
        await policy.resolve("evil.test", 443)
    with pytest.raises(BlockedDestination, match="allowlist"):
        await policy.resolve("example.com.evil.test", 443)


async def test_unresolvable_host_is_probe_error() -> None:
    with pytest.raises(ProbeError):
        await DestinationPolicy(allow_private=True).resolve("does-not-exist.invalid", 80)
