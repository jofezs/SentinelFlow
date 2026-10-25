from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError

from sentinelflow_gateway.deps import ProjectDep, SessionDep, require_admin
from sentinelflow_gateway.models import ApiKey, Project
from sentinelflow_gateway.schemas import ProjectCreate, ProjectCreated, ProjectRead
from sentinelflow_gateway.security import generate_api_key

router = APIRouter(prefix="/v1/projects", tags=["projects"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
async def create_project(body: ProjectCreate, session: SessionDep) -> ProjectCreated:
    """Create a project and its first API key (admin only)."""
    project = Project(name=body.name)
    key = generate_api_key()
    session.add(project)
    try:
        await session.flush()
        session.add(ApiKey(project_id=project.id, prefix=key.prefix, key_hash=key.key_hash))
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "project name already exists") from exc
    return ProjectCreated(
        id=project.id, name=project.name, created_at=project.created_at, api_key=key.plaintext
    )


@router.get("/me")
async def current_project(project: ProjectDep) -> ProjectRead:
    """Return the project that owns the presented API key."""
    return ProjectRead.model_validate(project)
