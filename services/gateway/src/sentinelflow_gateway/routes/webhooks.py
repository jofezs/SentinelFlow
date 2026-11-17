from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from sentinelflow_gateway import webhooks
from sentinelflow_gateway.deps import ProjectDep, SessionDep
from sentinelflow_gateway.models import Project, WebhookDelivery
from sentinelflow_gateway.schemas import DeliveryRead, WebhookCreated, WebhookRead, WebhookUpdate

router = APIRouter(prefix="/v1/projects/me/webhook", tags=["webhooks"])


def _read(project: Project) -> WebhookRead:
    if not project.webhook_url or not project.webhook_secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no webhook configured")
    return WebhookRead(
        url=project.webhook_url,
        events=project.webhook_events or list(webhooks.DEFAULT_EVENTS),
        secret_hint=project.webhook_secret[:10] + "...",
    )


@router.put("")
async def set_webhook(
    body: WebhookUpdate, project: ProjectDep, session: SessionDep
) -> WebhookCreated:
    """Create or replace the project's webhook. Always issues a new signing secret."""
    secret = webhooks.generate_secret()
    project.webhook_url = body.url
    project.webhook_events = body.events
    project.webhook_secret = secret
    await session.commit()
    return WebhookCreated(**_read(project).model_dump(), secret=secret)


@router.get("")
async def get_webhook(project: ProjectDep) -> WebhookRead:
    return _read(project)


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(project: ProjectDep, session: SessionDep) -> None:
    project.webhook_url = project.webhook_secret = project.webhook_events = None
    await session.commit()


@router.post("/test", status_code=status.HTTP_202_ACCEPTED)
async def send_test_event(project: ProjectDep, session: SessionDep) -> DeliveryRead:
    """Queue a signed 'ping' delivery to check the receiver end to end."""
    _read(project)  # 404 if not configured
    delivery = webhooks.enqueue(session, project, "ping", {"message": "SentinelFlow webhook test"})
    await session.commit()
    return DeliveryRead.model_validate(delivery)


@router.get("/deliveries")
async def list_deliveries(
    project: ProjectDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[DeliveryRead]:
    """Most recent deliveries first, with attempt counts and last response."""
    rows = await session.scalars(
        select(WebhookDelivery)
        .where(WebhookDelivery.project_id == project.id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(limit)
    )
    return [DeliveryRead.model_validate(d) for d in rows]
