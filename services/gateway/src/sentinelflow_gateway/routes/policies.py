from fastapi import APIRouter, HTTPException, status
from pydantic import ValidationError

from sentinelflow_common.policies import POLICIES
from sentinelflow_gateway.deps import ProjectDep, SessionDep
from sentinelflow_gateway.schemas import PolicyConfigRead, PolicyConfigUpdate, PolicyRead

router = APIRouter(tags=["policies"])


@router.get("/v1/policies")
async def list_policies(_: ProjectDep) -> list[PolicyRead]:
    """The policy catalog: what can be enabled and configured per project."""
    return [
        PolicyRead(
            id=spec.id,
            title=spec.title,
            description=spec.description,
            applies_to=sorted(spec.applies_to),
            params_schema=spec.params.model_json_schema() if spec.params else None,
        )
        for spec in POLICIES.values()
    ]


@router.get("/v1/projects/me/policy")
async def get_policy_config(project: ProjectDep) -> PolicyConfigRead:
    config = project.policy()
    return PolicyConfigRead(
        enabled=list(config.enabled) if config.enabled is not None else None,
        params=config.params,
    )


@router.put("/v1/projects/me/policy")
async def update_policy_config(
    body: PolicyConfigUpdate, project: ProjectDep, session: SessionDep
) -> PolicyConfigRead:
    """Replace the project's policy config. Applies to scans evaluated from now on;
    past decisions keep the config snapshot they were evaluated with."""
    try:
        config = body.to_config()
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    project.policy_config = config.model_dump(mode="json")
    session.add(project)
    await session.commit()
    return PolicyConfigRead(
        enabled=list(config.enabled) if config.enabled is not None else None,
        params=config.params,
    )
