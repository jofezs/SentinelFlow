# syntax=docker/dockerfile:1
# OPA with SentinelFlow policies baked in: policies are versioned and shipped
# with the image, so what runs in production is exactly what CI tested.
# Build context: repository root.

FROM openpolicyagent/opa:1.21.1@sha256:d3a9a6bd4fbcb0f4403294b0d0b239b07be163ac118a46df7d50045b52e52053
COPY services/policy-engine/policies /policies
# Image runs as non-root UID 1000. Liveness/readiness: HTTP GET /health
# (Kubernetes httpGet probe; the image is distroless, so no shell-based check).
HEALTHCHECK --interval=15s --timeout=5s CMD ["/opa", "version"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "--log-level=error", "--ignore=*_test.rego", "/policies"]
