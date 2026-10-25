# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/gateway services/gateway
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/gateway

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY services/gateway/alembic.ini ./
COPY services/gateway/migrations ./migrations
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["uvicorn", "sentinelflow_gateway.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
