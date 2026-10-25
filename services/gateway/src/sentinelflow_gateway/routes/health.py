from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from sentinelflow_gateway.deps import SessionDep

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    """Process is up. Used by Kubernetes liveness probes."""
    return {"status": "ok"}


@router.get("/readyz")
async def readiness(session: SessionDep) -> dict[str, str]:
    """Dependencies are reachable. Used by Kubernetes readiness probes."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from exc
    return {"status": "ready"}
