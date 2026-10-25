import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinelflow_gateway import __version__
from sentinelflow_gateway.config import Settings
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.routes import health, policies, projects, scans


def create_app(settings: Settings | None = None, database: Database | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn sentinelflow_gateway.main:create_app --factory"""
    settings = settings or Settings()  # admin_token is read from the environment
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await app.state.database.dispose()

    app = FastAPI(
        title="SentinelFlow Gateway",
        version=__version__,
        description="Submit container images, Dockerfiles, and API endpoints for security audit.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database or Database(settings.database_url)

    app.include_router(health.router)
    app.include_router(projects.router)
    app.include_router(policies.router)
    app.include_router(scans.router)
    return app
