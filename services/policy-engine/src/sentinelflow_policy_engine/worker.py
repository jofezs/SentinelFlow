"""Policy engine worker. Run with: python -m sentinelflow_policy_engine.worker

Fails closed: if OPA is unavailable or returns no decision, the handler raises,
the message is nak'ed and redelivered with backoff. A scan is never reported as
passing without an actual policy decision.
"""

import asyncio
import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelflow_common.bus import AnyEvent, JetStreamBus, install_signal_handlers
from sentinelflow_common.events import PolicyEvaluationRequested, Subjects
from sentinelflow_common.health import Heartbeat
from sentinelflow_common.worker import configure_logging
from sentinelflow_policy_engine.engine import evaluate
from sentinelflow_policy_engine.opa import OpaClient

logger = logging.getLogger("sentinelflow_policy_engine.worker")


class EngineSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", extra="ignore")

    nats_url: str = "nats://127.0.0.1:4222"
    opa_url: str = "http://127.0.0.1:8181"
    log_level: str = "INFO"


async def main() -> None:
    settings = EngineSettings()
    configure_logging(settings.log_level)
    opa = OpaClient(settings.opa_url)
    await opa.wait_ready()
    bus = await JetStreamBus.connect(settings.nats_url, name="policy-engine")
    await bus.ensure_stream()

    async def on_event(event: AnyEvent) -> None:
        if not isinstance(event, PolicyEvaluationRequested):
            return
        decision = await evaluate(opa, event)
        # Keyed on the request's event id: duplicates of this request are dropped,
        # while a later re-evaluation of the same scan is still delivered.
        await bus.publish_event(
            Subjects.POLICY_EVALUATED, decision, msg_id=f"{event.event_id}.decision"
        )
        logger.info(
            "scan %s policy %s (%d violations)",
            event.scan_id,
            "passed" if decision.passed else "FAILED",
            len(decision.violations),
        )

    stop = asyncio.Event()
    install_signal_handlers(stop)
    try:
        await bus.consume(
            Subjects.POLICY_REQUESTED, "policy-engine", on_event, stop, heartbeat=Heartbeat()
        )
    finally:
        await bus.close()
        await opa.close()


if __name__ == "__main__":
    asyncio.run(main())
