"""Dockerfile scanner worker. Run with: python -m sentinelflow_dockerfile_scanner.worker"""

import asyncio
import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelflow_common.bus import AnyEvent, JetStreamBus, install_signal_handlers
from sentinelflow_common.events import ScanRequested, Subjects, TargetType
from sentinelflow_dockerfile_scanner.scanner import handle_request

logger = logging.getLogger("sentinelflow_dockerfile_scanner.worker")


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", extra="ignore")

    nats_url: str = "nats://127.0.0.1:4222"
    hadolint_binary: str = "hadolint"
    scan_timeout: float = 30.0
    log_level: str = "INFO"


async def main() -> None:
    settings = ScannerSettings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    bus = await JetStreamBus.connect(settings.nats_url, name="scanner-dockerfile")
    await bus.ensure_stream()

    async def on_event(event: AnyEvent) -> None:
        if not isinstance(event, ScanRequested):
            return
        logger.info("scanning %s", event.scan_id)
        result = await handle_request(event, settings.hadolint_binary, settings.scan_timeout)
        if result is not None:
            # Deterministic msg id: a redelivered request yields a deduplicated result.
            await bus.publish_event(
                Subjects.SCAN_COMPLETED, result, msg_id=f"{event.scan_id}.completed"
            )
            logger.info(
                "scan %s %s with %d findings", event.scan_id, result.status, len(result.findings)
            )

    stop = asyncio.Event()
    install_signal_handlers(stop)
    try:
        await bus.consume(
            Subjects.scan_requested(TargetType.DOCKERFILE),
            "scanner-dockerfile",
            on_event,
            stop,
            ack_wait=settings.scan_timeout * 2,
        )
    finally:
        await bus.close()


if __name__ == "__main__":
    asyncio.run(main())
