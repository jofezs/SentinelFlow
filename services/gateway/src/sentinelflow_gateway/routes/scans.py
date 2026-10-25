import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from sentinelflow_common.events import ScanRequested, Subjects, TargetType
from sentinelflow_gateway.deps import ProjectDep, SessionDep
from sentinelflow_gateway.models import OutboxEvent, Scan, ScanState
from sentinelflow_gateway.schemas import ScanCreate, ScanDetail, ScanList, ScanRead

router = APIRouter(prefix="/v1/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_scan(body: ScanCreate, project: ProjectDep, session: SessionDep) -> ScanRead:
    """Queue a scan. Processing is asynchronous; poll GET /v1/scans/{id} for status."""
    scan = Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        target_type=body.target_type,
        target=body.target,
    )
    event = ScanRequested(
        scan_id=scan.id,
        project_id=project.id,
        target_type=body.target_type,
        target=body.target,
    )
    # Scan row and its event commit atomically; the outbox relay publishes it.
    session.add_all([scan, OutboxEvent.for_event(Subjects.scan_requested(body.target_type), event)])
    await session.commit()
    return ScanRead.model_validate(scan)


@router.get("")
async def list_scans(
    project: ProjectDep,
    session: SessionDep,
    status_filter: Annotated[ScanState | None, Query(alias="status")] = None,
    target_type: TargetType | None = None,
    policy_passed: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    query = select(Scan).where(Scan.project_id == project.id)
    if status_filter is not None:
        query = query.where(Scan.status == status_filter)
    if target_type is not None:
        query = query.where(Scan.target_type == target_type)
    if policy_passed is not None:
        query = query.where(Scan.policy_passed.is_(policy_passed))

    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = await session.scalars(
        query.order_by(Scan.created_at.desc(), Scan.id).limit(limit).offset(offset)
    )
    return ScanList(
        items=[ScanRead.model_validate(s) for s in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}")
async def get_scan(scan_id: uuid.UUID, project: ProjectDep, session: SessionDep) -> ScanDetail:
    # Scoped by project: another tenant's scan is indistinguishable from a missing one.
    scan = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == project.id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return ScanDetail.model_validate(scan)
