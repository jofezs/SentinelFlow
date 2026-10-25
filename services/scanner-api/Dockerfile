# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/scanner-api services/scanner-api
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/scanner-api

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
USER 10001
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-c", "import sentinelflow_api_scanner"]
CMD ["python", "-m", "sentinelflow_api_scanner.worker"]
