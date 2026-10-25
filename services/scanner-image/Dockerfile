# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

# Pinned by digest: a scanner binary is a high-value supply-chain target.
FROM aquasec/trivy:0.58.1@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7 AS trivy

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/scanner-image services/scanner-image
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/scanner-image

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/cache/trivy \
    && chown 10001:10001 /var/cache/trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /opt/venv /opt/venv
USER 10001
# The loop blocks for the duration of one image scan (up to the 600s scan timeout).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
    CMD ["python", "-m", "sentinelflow_common.health", "--max-age", "720"]
CMD ["python", "-m", "sentinelflow_image_scanner.worker"]
