# syntax=docker/dockerfile:1
# Policy engine worker. Build context: repository root (needs libs/common).
# OPA itself runs as a separate sidecar image built from opa.Dockerfile.

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/policy-engine/pyproject.toml services/policy-engine/pyproject.toml
COPY services/policy-engine/src services/policy-engine/src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/policy-engine

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
USER 10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s \
    CMD ["python", "-m", "sentinelflow_common.health", "--max-age", "60"]
CMD ["python", "-m", "sentinelflow_policy_engine.worker"]
