import logging

from sentinelflow_common.bus import AnyEvent
from sentinelflow_common.events import (
    PolicyEvaluated,
    PolicyEvaluationRequested,
    ScanCompleted,
    ScanStatus,
    Subjects,
)
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.models import OutboxEvent, Project, Scan, ScanState, utcnow

logger = logging.getLogger(__name__)


class ResultsIngester:
    """Applies scan.completed and policy.evaluated events to the database. Idempotent."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def __call__(self, event: AnyEvent) -> None:
        if isinstance(event, ScanCompleted):
            await self.apply_scan_result(event)
        elif isinstance(event, PolicyEvaluated):
            await self.apply_policy_decision(event)

    async def apply_scan_result(self, event: ScanCompleted) -> None:
        async with self._db.session() as session:
            scan = await session.get(Scan, event.scan_id, with_for_update=True)
            if scan is None:
                logger.warning("scan.completed for unknown scan %s; ignoring", event.scan_id)
                return
            if scan.status.is_terminal:
                logger.info("scan %s already %s; ignoring duplicate", scan.id, scan.status)
                return

            succeeded = event.status == ScanStatus.SUCCEEDED
            scan.status = ScanState.COMPLETED if succeeded else ScanState.FAILED
            scan.scanner = event.scanner
            scan.findings = [f.model_dump(mode="json") for f in event.findings]
            scan.max_severity = event.max_severity()
            scan.error = event.error
            scan.completed_at = event.occurred_at

            if succeeded:
                # Same transaction as the result: the policy request cannot be lost.
                project = await session.get(Project, scan.project_id)
                if project is None:  # impossible while the FK holds; fail loudly if not
                    raise RuntimeError(f"project {scan.project_id} missing for scan {scan.id}")
                request = PolicyEvaluationRequested(
                    scan_id=scan.id,
                    project_id=scan.project_id,
                    target_type=scan.target_type,
                    target=scan.target,
                    scanner=event.scanner,
                    findings=event.findings,
                    config=project.policy(),
                )
                session.add(OutboxEvent.for_event(Subjects.POLICY_REQUESTED, request))
            await session.commit()
        logger.info("scan %s -> %s (%d findings)", event.scan_id, scan.status, len(event.findings))

    async def apply_policy_decision(self, event: PolicyEvaluated) -> None:
        async with self._db.session() as session:
            scan = await session.get(Scan, event.scan_id, with_for_update=True)
            if scan is None:
                logger.warning("policy.evaluated for unknown scan %s; ignoring", event.scan_id)
                return
            if scan.policy_evaluated_at is not None:
                logger.info("scan %s policy already recorded; ignoring duplicate", scan.id)
                return
            scan.policy_passed = event.passed
            scan.policy_violations = [v.model_dump(mode="json") for v in event.violations]
            scan.policy_evaluated_at = utcnow()
            await session.commit()
        logger.info("scan %s policy %s", event.scan_id, "passed" if event.passed else "FAILED")
