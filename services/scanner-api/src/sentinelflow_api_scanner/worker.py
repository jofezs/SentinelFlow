"""API endpoint scanner worker. Run with: python -m sentinelflow_api_scanner.worker"""

import asyncio
from functools import partial

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelflow_api_scanner.scanner import handle_request
from sentinelflow_api_scanner.ssrf import DestinationPolicy
from sentinelflow_common.events import TargetType
from sentinelflow_common.worker import configure_logging, run_scanner_worker


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", extra="ignore")

    nats_url: str = "nats://127.0.0.1:4222"
    probe_timeout: float = 10.0
    allowed_ports: str = "80,443,8080,8443"  # comma-separated
    allowed_hosts: str = ""  # comma-separated fnmatch patterns, e.g. "*.example.com"
    log_level: str = "INFO"

    def policy(self) -> DestinationPolicy:
        return DestinationPolicy(
            allowed_ports=frozenset(int(p) for p in self.allowed_ports.split(",") if p.strip()),
            allowed_hosts=tuple(h.strip() for h in self.allowed_hosts.split(",") if h.strip()),
        )


async def main() -> None:
    settings = ScannerSettings()
    configure_logging(settings.log_level)
    await run_scanner_worker(
        name="scanner-api",
        target_type=TargetType.API_ENDPOINT,
        handle=partial(handle_request, policy=settings.policy(), timeout=settings.probe_timeout),
        nats_url=settings.nats_url,
        ack_wait=settings.probe_timeout * 3 * 10 + 30,  # GET + TLS per request, batch of 10
    )


if __name__ == "__main__":
    asyncio.run(main())
