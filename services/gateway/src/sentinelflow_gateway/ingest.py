import logging

from sentinelflow_common.bus import AnyEvent
from sentinelflow_common.events import ScanCompleted, ScanStatus
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import Scan, ScanState

logger = logging.getLogger(__name__)


class ResultsIngester:
    """Applies scan.completed events to the scans table. Idempotent."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def __call__(self, event: AnyEvent) -> None:
        if isinstance(event, ScanCompleted):
            await self.apply(event)

    async def apply(self, event: ScanCompleted) -> None:
        async with self._db.session() as session:
            scan = await session.get(Scan, event.scan_id, with_for_update=True)
            if scan is None:
                logger.warning("scan.completed for unknown scan %s; ignoring", event.scan_id)
                return
            if scan.status.is_terminal:
                logger.info("scan %s already %s; ignoring duplicate", scan.id, scan.status)
                return

            scan.status = (
                ScanState.COMPLETED if event.status == ScanStatus.SUCCEEDED else ScanState.FAILED
            )
            scan.scanner = event.scanner
            scan.findings = [f.model_dump(mode="json") for f in event.findings]
            scan.max_severity = event.max_severity()
            scan.error = event.error
            scan.completed_at = event.occurred_at
            await session.commit()
        logger.info("scan %s -> %s (%d findings)", event.scan_id, scan.status, len(event.findings))
