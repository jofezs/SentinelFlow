# SentinelFlow

**Automated Cloud Infrastructure & Security Audit Engine**

[![CI](https://github.com/jofezs/SentinelFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/jofezs/SentinelFlow/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

SentinelFlow is an event-driven microservices platform. Users submit **container images**,
**Dockerfiles**, or **API endpoints**; the system scans them for security issues, evaluates the
results against policy-as-code, tracks compliance metrics over time, and fires signed webhooks
when something violates policy.

## Architecture

```
            ┌──────────────┐
 User ───▶  │ API Gateway  │  FastAPI · auth · submit scans · query results
            └──────┬───────┘
                   │ scan.requested.<target>
            ┌──────▼───────┐
            │ Message Bus  │  NATS JetStream
            └──┬────┬────┬─┘
     ┌─────────┘    │    └──────────┐
┌────▼─────┐ ┌──────▼─────┐ ┌───────▼──────┐
│ Image    │ │ Dockerfile │ │ API Endpoint │   Scanner workers
│ Scanner  │ │ Scanner    │ │ Scanner      │   (scale independently)
│ (Trivy)  │ │ (Hadolint) │ │ (TLS/headers)│
└────┬─────┘ └──────┬─────┘ └───────┬──────┘
     └──────────────┼───────────────┘ scan.completed
             ┌──────▼───────┐
             │ Policy Engine│  OPA / Rego
             └──────┬───────┘ policy.evaluated
       ┌────────────┼──────────────┐
┌──────▼─────┐ ┌────▼──────┐ ┌─────▼──────┐
│ PostgreSQL │ │ Notifier  │ │ Prometheus │──▶ Grafana
│ (results)  │ │ (webhooks)│ │ (metrics)  │
└────────────┘ └───────────┘ └────────────┘
```

Services communicate only through versioned event contracts defined in
[`libs/common`](libs/common/src/sentinelflow_common/events.py).

## Tech stack

| Area | Tools |
|---|---|
| Services | Python 3.12, FastAPI, Pydantic, SQLAlchemy |
| Messaging | NATS JetStream |
| Scanning | Trivy, Hadolint, custom API probes |
| Policy | Open Policy Agent (Rego) |
| Storage & metrics | PostgreSQL, Prometheus, Grafana |
| Platform | Docker, Kubernetes (kind), Helm |
| CI/CD & DevSecOps | GitHub Actions, Ruff, mypy, pytest, gitleaks, CodeQL, Trivy, cosign, Syft |

## Roadmap

- [x] **Phase 0** – Repo tooling, CI, shared event contracts
- [ ] **Phase 1** – API gateway (FastAPI + PostgreSQL, API-key auth)
- [ ] **Phase 2** – Event bus + Dockerfile scanner, `docker compose` stack
- [ ] **Phase 3** – Image scanner (Trivy) + API endpoint scanner (SSRF-guarded)
- [ ] **Phase 4** – Policy engine (OPA/Rego)
- [ ] **Phase 5** – Webhook notifier (HMAC-signed, retries) + Prometheus/Grafana
- [ ] **Phase 6** – Helm chart, kind deployment, HPA, NetworkPolicies
- [ ] **Phase 7** – Full CI/CD: image build, self-scan, e2e on kind, signed releases
- [ ] **Phase 8** – Threat model, docs, demo

## Local development

Requirements: Python 3.12, Docker Desktop. Later phases also use kind and Helm.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install

pytest              # run tests
ruff check .        # lint
mypy libs/common/src
```

## Responsible use

The API endpoint scanner performs non-destructive checks (TLS configuration, security headers,
CORS) and is restricted to an allowlist of targets. Only scan systems you own or are authorized
to test.

## License

[MIT](LICENSE)
