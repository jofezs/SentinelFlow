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
- [x] **Phase 1** – API gateway (FastAPI + PostgreSQL, API-key auth)
- [x] **Phase 2** – Event bus (NATS JetStream), transactional outbox, Dockerfile scanner
- [ ] **Phase 3** – Image scanner (Trivy) + API endpoint scanner (SSRF-guarded)
- [ ] **Phase 4** – Policy engine (OPA/Rego)
- [ ] **Phase 5** – Webhook notifier (HMAC-signed, retries) + Prometheus/Grafana
- [ ] **Phase 6** – Helm chart, kind deployment, HPA, NetworkPolicies
- [ ] **Phase 7** – Full CI/CD: image build, self-scan, e2e on kind, signed releases
- [ ] **Phase 8** – Threat model, docs, demo

## Quick start

Requirements: Docker Desktop.

```bash
cp .env.example .env          # then set SENTINELFLOW_ADMIN_TOKEN to a long random value
docker compose up --build -d --wait
```

Interactive API docs: <http://localhost:8000/docs>

Run the end-to-end smoke test (submits an insecure Dockerfile and checks the findings):

```bash
python scripts/smoke_test.py
```

```
status=completed max_severity=critical findings=7
  [critical] SF002   line 2   Secret 'DB_PASSWORD' hard-coded in ENV
  [    high] SF001   line 1   Container runs as root (no USER instruction)
  [    high] SF005   line 3   Remote script piped directly into a shell
  [  medium] DL3007  line 1   Using latest is prone to errors if the image will ever update...
  [  medium] SF008   line 4   SSH port 22 exposed
  ...
```

```bash
# 1. Create a project (admin). The response contains an API key, shown only once.
curl -s -X POST localhost:8000/v1/projects \
  -H "Authorization: Bearer $SENTINELFLOW_ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "demo"}'

# 2. Submit a scan with the project's API key
curl -s -X POST localhost:8000/v1/scans \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"target_type": "image", "target": "nginx:1.27"}'

# 3. Check status
curl -s localhost:8000/v1/scans/$SCAN_ID -H "X-API-Key: $API_KEY"
```

### API overview

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/projects` | Admin bearer token | Create a project and its API key |
| `GET` | `/v1/projects/me` | API key | Current project |
| `POST` | `/v1/scans` | API key | Submit an image, Dockerfile, or API endpoint (202 Accepted) |
| `GET` | `/v1/scans` | API key | List scans (`status`, `target_type`, `limit`, `offset`) |
| `GET` | `/v1/scans/{id}` | API key | Scan details |
| `GET` | `/healthz`, `/readyz` | — | Liveness / readiness probes |

### Security design (gateway)

- **API keys** are 256-bit random tokens; only a SHA-256 hash and a lookup prefix are stored, and
  comparisons are constant-time.
- **Tenant isolation**: every query is scoped to the caller's project; another tenant's scan
  returns `404`, not `403`, so IDs can't be probed.
- **Strict input validation**: image references follow Docker's grammar and must start with an
  alphanumeric (blocking CLI flag injection into scanners); URLs must be http(s) with no embedded
  credentials; request bodies reject unknown fields.
- **Container hardening**: multi-stage build, non-root UID, no shell for the runtime user, ports
  bound to localhost in Compose.

### Event flow and delivery guarantees

```
POST /v1/scans ─▶ [scans + outbox_events]   ◀── single DB transaction
                          │
        gateway-worker: outbox relay ──▶ NATS JetStream  (dedup on Nats-Msg-Id)
                                              │ scan.requested.dockerfile
                                     scanner-dockerfile (Hadolint + SF rules)
                                              │ scan.completed
        gateway-worker: results ingester ◀────┘ ──▶ scans.status / findings
```

- **Transactional outbox**: the scan row and its event commit together, so a broker outage can
  never leave a scan without its event. Relay rows are claimed with `FOR UPDATE SKIP LOCKED`, so
  worker replicas scale horizontally.
- **At-least-once + idempotency**: publishers set `Nats-Msg-Id` (JetStream drops duplicates);
  the results ingester ignores results for scans already in a terminal state.
- **Poison messages** are terminated rather than retried forever; handler failures are redelivered
  with exponential backoff (capped at `max_deliver`).
- **Graceful shutdown**: workers drain on SIGTERM (Kubernetes pod termination).

### Dockerfile rules

Hadolint covers build best practices; SentinelFlow adds security-focused rules:

| ID | Severity | Detects |
|---|---|---|
| SF001 | High | Final stage runs as root (no `USER`, or `USER root`) |
| SF002 | Critical | Secrets hard-coded in `ENV` (value is never echoed into the finding) |
| SF003 | Critical / Medium | Secrets passed as build `ARG` (with / without default) |
| SF004 | Medium | `ADD <url>` without `--checksum` |
| SF005 | High | `curl \| sh` / `wget \| bash` |
| SF006 | High | TLS verification disabled (`curl -k`, `--no-check-certificate`, `strict-ssl false`, ...) |
| SF007 | Medium | World-writable permissions (`chmod 777`) |
| SF008 | Medium | SSH port 22 exposed |
| SF009 | Low | No `HEALTHCHECK` |

Untrusted Dockerfiles are passed to Hadolint on **stdin** via `exec` (no shell, no temp files),
with a timeout.

## Development

Requirements: Python 3.12, Docker Desktop. Later phases also use kind and Helm.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install

pytest                                         # tests (in-memory SQLite by default)
ruff check . && ruff format --check .          # lint
mypy libs/common/src services/gateway/src services/scanner-dockerfile/src
```

With the Compose stack running, run the suite against real Postgres and NATS (as CI does):

```bash
export SENTINELFLOW_TEST_DATABASE_URL=postgresql+asyncpg://sentinelflow:sentinelflow@127.0.0.1:5432/sentinelflow_test
export SENTINELFLOW_TEST_NATS_URL=nats://127.0.0.1:4222
pytest
```

CI also runs `alembic check` (migrations must match the ORM models) and the end-to-end smoke test
against the full Compose stack.

## Responsible use

The API endpoint scanner performs non-destructive checks (TLS configuration, security headers,
CORS) and is restricted to an allowlist of targets. Only scan systems you own or are authorized
to test.

## License

[MIT](LICENSE)
