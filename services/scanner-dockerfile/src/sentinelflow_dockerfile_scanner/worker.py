"""Dockerfile scanner worker. Run with: python -m sentinelflow_dockerfile_scanner.worker"""

import asyncio
from functools import partial

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelflow_common.events import TargetType
from sentinelflow_common.worker import configure_logging, run_scanner_worker
from sentinelflow_dockerfile_scanner.scanner import handle_request


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", extra="ignore")

    nats_url: str = "nats://127.0.0.1:4222"
    hadolint_binary: str = "hadolint"
    scan_timeout: float = 30.0
    log_level: str = "INFO"


async def main() -> None:
    settings = ScannerSettings()
    configure_logging(settings.log_level)
    await run_scanner_worker(
        name="scanner-dockerfile",
        target_type=TargetType.DOCKERFILE,
        handle=partial(
            handle_request, hadolint_binary=settings.hadolint_binary, timeout=settings.scan_timeout
        ),
        nats_url=settings.nats_url,
        ack_wait=settings.scan_timeout * 2 * 10,  # batch of 10, each up to scan_timeout
    )


if __name__ == "__main__":
    asyncio.run(main())
