import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from sentinelflow_common.events import ScanRequested, Subjects, TargetType
from sentinelflow_gateway.deps import ProjectDep, PublisherDep, SessionDep
from sentinelflow_gateway.models import Scan, ScanState
from sentinelflow_gateway.schemas import ScanCreate, ScanList, ScanRead

router = APIRouter(prefix="/v1/scans", tags=["scans"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_scan(
    body: ScanCreate, project: ProjectDep, session: SessionDep, publisher: PublisherDep
) -> ScanRead:
    """Queue a scan. Processing is asynchronous; poll GET /v1/scans/{id} for status."""
    scan = Scan(project_id=project.id, target_type=body.target_type, target=body.target)
    session.add(scan)
    await session.commit()

    # TODO(phase-2): publish via a transactional outbox so a broker outage
    # cannot leave a committed scan without its event.
    await publisher.publish(
        Subjects.scan_requested(scan.target_type),
        ScanRequested(
            scan_id=scan.id,
            project_id=project.id,
            target_type=scan.target_type,
            target=scan.target,
        ),
    )
    return ScanRead.model_validate(scan)


@router.get("")
async def list_scans(
    project: ProjectDep,
    session: SessionDep,
    status_filter: Annotated[ScanState | None, Query(alias="status")] = None,
    target_type: TargetType | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    query = select(Scan).where(Scan.project_id == project.id)
    if status_filter is not None:
        query = query.where(Scan.status == status_filter)
    if target_type is not None:
        query = query.where(Scan.target_type == target_type)

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
async def get_scan(scan_id: uuid.UUID, project: ProjectDep, session: SessionDep) -> ScanRead:
    # Scoped by project: another tenant's scan is indistinguishable from a missing one.
    scan = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == project.id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return ScanRead.model_validate(scan)
