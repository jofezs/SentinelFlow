# syntax=docker/dockerfile:1
# Build context: repository root (needs libs/common).

FROM hadolint/hadolint:v2.12.0 AS hadolint

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY libs/common libs/common
COPY services/scanner-dockerfile services/scanner-dockerfile
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ./libs/common ./services/scanner-dockerfile

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=hadolint /bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /opt/venv /opt/venv
USER 10001
HEALTHCHECK --interval=30s --timeout=5s CMD ["hadolint", "--version"]
CMD ["python", "-m", "sentinelflow_dockerfile_scanner.worker"]
