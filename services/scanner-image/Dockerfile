# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

# Pinned by digest: a scanner binary is a high-value supply-chain target.
FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/scanner-image services/scanner-image
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/scanner-image

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Patch OS packages: upstream slim images lag Debian security fixes.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/cache/trivy \
    && chown 10001:10001 /var/cache/trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /opt/venv /opt/venv
USER 10001
# The loop blocks for the duration of one image scan (up to the 600s scan timeout).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
    CMD ["python", "-m", "sentinelflow_common.health", "--max-age", "720"]
CMD ["python", "-m", "sentinelflow_image_scanner.worker"]
