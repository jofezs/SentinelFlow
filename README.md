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
- [x] **Phase 3** – Image scanner (Trivy) + API endpoint scanner (SSRF-guarded)
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

Run the end-to-end smoke test (one scan of each type, plus an SSRF attempt):

```bash
python scripts/smoke_test.py
```

```
[dockerfile] 'FROM ubuntu:latest\nENV DB_PASSWORD=hunter2...' -> completed (max=critical, findings=7)
  [critical] SF002            Secret 'DB_PASSWORD' hard-coded in ENV
  [    high] SF001            Container runs as root (no USER instruction)
  [    high] SF005            Remote script piped directly into a shell

[image] 'alpine:3.18.0' -> completed (max=critical, findings=49)
  [critical] CVE-2022-48174   busybox 1.36.0-r9: busybox: stack overflow vulnerability in ash.c
  [    high] CVE-2023-5363    libcrypto3 3.1.0-r4: openssl: Incorrect cipher key and IV length

[api] 'https://example.com/' -> completed (max=medium, findings=4)
  [  medium] API010           Missing Strict-Transport-Security header
  [     low] API013           Missing X-Content-Type-Options: nosniff

[ssrf] 'http://169.254.169.254/latest/meta-data/' -> failed
       destination not allowed: 169.254.169.254 is not a public address
PASS
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

### Image scanner

[Trivy](https://github.com/aquasecurity/trivy) scans images for OS/language-package CVEs and
embedded secrets. It pulls directly from the registry, so the scanner **never needs the Docker
socket** (mounting it would grant root on the host). The image reference is passed after `--`, so
even a flag-shaped reference is never parsed as an option. The Trivy image is pinned by digest.
Findings are deduplicated, ordered by severity then fixability, and capped at 500 per scan.

### API endpoint scanner and SSRF protection

The API scanner fetches user-supplied URLs, which makes it a classic **SSRF** target. The guard is
enforced at the connection layer rather than as an up-front URL check:

- Every TCP connection, including each redirect hop and the separate TLS probe, goes through a
  custom `httpcore` network backend that resolves the host, requires **every** resolved address to
  be public, and connects to exactly that validated IP. This defeats **DNS rebinding**.
- Rejected: loopback, RFC 1918, link-local (cloud metadata `169.254.169.254`), CGNAT, multicast,
  reserved, and IPv4-mapped IPv6. Verified against decimal/hex/octal IP encodings, `localtest.me`,
  and `nip.io` names.
- Ports limited to 80/443/8080/8443; optional host allowlist (`SENTINELFLOW_ALLOWED_HOSTS`);
  environment proxies are ignored (they would bypass the guard).
- Non-destructive: one `GET` (body never read) and one TLS handshake, with an identifying
  `User-Agent`.

| ID | Detects |
|---|---|
| API001 | Plaintext HTTP |
| API002–004 | Weak TLS version, invalid certificate, certificate expiring within 30 days |
| API010–014 | Missing/weak HSTS, missing CSP, missing `nosniff`, no clickjacking protection |
| API015 | Version disclosure (`Server`, `X-Powered-By`) |
| API016 | Cookies without `Secure` / `HttpOnly` / `SameSite` |
| API020–023 | CORS: arbitrary origin reflection (critical with credentials), `null`, `*` |

## Development

Requirements: Python 3.12, Docker Desktop. Later phases also use kind and Helm.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install

pytest                                         # tests (in-memory SQLite by default)
ruff check . && ruff format --check .          # lint
mypy libs/common/src services/*/src
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
CORS), refuses internal destinations, and can be restricted to a host allowlist. Only scan systems
you own or are authorized to test.

## License

[MIT](LICENSE)
