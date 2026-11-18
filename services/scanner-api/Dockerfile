# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/scanner-api services/scanner-api
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/scanner-api

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Patch OS packages: upstream slim images lag Debian security fixes.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
USER 10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
    CMD ["python", "-m", "sentinelflow_common.health", "--max-age", "60"]
CMD ["python", "-m", "sentinelflow_api_scanner.worker"]
