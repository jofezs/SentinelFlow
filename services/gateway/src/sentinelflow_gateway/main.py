import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from sentinelflow_common.metrics import serve_metrics
from sentinelflow_gateway import __version__
from sentinelflow_gateway.config import Settings
from sentinelflow_gateway.db import Database
from sentinelflow_gateway.metrics import HTTP_LATENCY, HTTP_REQUESTS
from sentinelflow_gateway.routes import health, policies, projects, scans, webhooks


def create_app(settings: Settings | None = None, database: Database | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn sentinelflow_gateway.main:create_app --factory"""
    settings = settings or Settings()  # admin_token is read from the environment
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        serve_metrics(settings.metrics_port)
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

    @app.middleware("http")
    async def record_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        # Label by route template (/v1/scans/{scan_id}), never the raw path, to keep
        # metric cardinality bounded.
        route = getattr(request.scope.get("route"), "path", "unmatched")
        HTTP_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        HTTP_LATENCY.labels(request.method, route).observe(time.perf_counter() - start)
        return response

    app.include_router(health.router)
    app.include_router(projects.router)
    app.include_router(policies.router)
    app.include_router(webhooks.router)
    app.include_router(scans.router)
    return app
