# SentinelFlow threat model

SentinelFlow accepts untrusted input from tenants (images, Dockerfiles, URLs), fetches untrusted
content from the internet, and issues **pass/fail compliance decisions** that people act on.
That makes two outcomes the worst case:

1. **A false PASS**: a vulnerable artefact is reported as compliant.
2. **The scanner as a weapon**: SentinelFlow is used to reach what an attacker can't
   (internal networks, cloud metadata, other tenants' data).

This document lists what we protect, where trust changes, and for each threat the control and
the code or test that enforces it. Open risks are listed as open.

*Method: STRIDE per trust boundary. Last reviewed 2026-11-18.*

## System and trust boundaries

```
                 TB1                               TB3
 Tenant ──API key──▶ Gateway ──▶ Postgres     Scanners ──▶ registries, user URLs,
 Admin ──token────▶   │             ▲           ▲  │        Dockerfile content (untrusted)
                      ▼             │           │  ▼
                   outbox ──▶ NATS JetStream ◀──┘ policy-engine ──▶ OPA (sidecar)
                                    │ TB2 (internal bus)
                                    ▼
                    Notifier ──signed HTTPS──▶ tenant webhook endpoints
                                         TB4

 TB5  source ──▶ GitHub Actions ──▶ GHCR (signed) ──▶ Kubernetes
```

| Boundary | Crossing | Trust change |
|---|---|---|
| **TB1** | Tenants and the admin → gateway API | Internet → platform |
| **TB2** | Services ↔ NATS ↔ services, services → Postgres | Between internal components with different exposure |
| **TB3** | Scanners → registries, user-supplied URLs, Dockerfile text | Platform → attacker-controlled content |
| **TB4** | Notifier → tenant webhook URLs | Platform → attacker-chosen destination |
| **TB5** | Source → CI → registry → cluster | Code → running software |

## Assets

| Asset | Why it matters |
|---|---|
| Policy decisions | The product. Integrity is paramount (see "false PASS" above). |
| Scan results | A tenant's unpatched vulnerabilities: a target list for an attacker. Confidential per tenant. |
| API keys, admin token | Full access to a tenant / to tenant creation. |
| Webhook signing secrets | Let a holder forge alerts to the tenant. |
| Cloud and cluster credentials | Reachable via metadata endpoints if SSRF succeeds. |
| Build pipeline and images | Whoever controls them controls every deployment. |

## Attackers considered

- **Malicious tenant**: has a valid API key; tries to read other tenants' data, abuse the
  scanners (SSRF, injection), or exhaust resources.
- **Hostile content**: a crafted image, Dockerfile, or HTTP endpoint that a legitimate tenant
  submits (or that an attacker tricks them into submitting).
- **Compromised component**: an attacker with code execution in one pod. Scanners are the most
  likely, because they parse untrusted data with large third-party tools.
- **Supply-chain attacker**: tampers with a dependency, base image, GitHub Action, or registry.
- **Network attacker** between SentinelFlow and webhook receivers.

Out of scope: a malicious cluster administrator, and compromise of GitHub, Sigstore, or the
Kubernetes control plane.

## Threats and controls

Status: **Mitigated** (control in place and tested) · **Partial** · **Open**.

### TB1: Tenants and admin → gateway

| ID | STRIDE | Threat | Control | Evidence | Status |
|---|---|---|---|---|---|
| T1 | S | Guess or steal an API key | 256-bit random keys; only SHA-256 hash + lookup prefix stored; constant-time compare | [security.py](../services/gateway/src/sentinelflow_gateway/security.py), [test_auth.py](../services/gateway/tests/test_auth.py) | Mitigated |
| T2 | I | Read another tenant's scans by ID | Every query scoped to the caller's project; foreign IDs return `404`, not `403` | [test_scans.py](../services/gateway/tests/test_scans.py) (`test_tenant_isolation`) | Mitigated |
| T3 | T | Inject CLI flags into scanners via the target (`--config=…` as an image ref) | Image refs must match Docker's grammar and start alphanumeric; Trivy gets the ref after `--`; Hadolint reads stdin via `exec`, no shell | [schemas.py](../services/gateway/src/sentinelflow_gateway/schemas.py), [test_trivy.py](../services/scanner-image/tests/test_trivy.py) | Mitigated |
| T4 | T | Oversized or malformed bodies | Size caps (Dockerfile 64 KiB, URL 2 KiB, image ref 255); unknown fields rejected | [schemas.py](../services/gateway/src/sentinelflow_gateway/schemas.py) | Mitigated |
| T5 | D | Flood the platform with expensive scans (image scans take minutes) | Scanners autoscale (HPA 1-4) and queue in JetStream, so work degrades instead of failing. **No per-tenant rate limit or quota yet.** | [values.yaml](../deploy/helm/sentinelflow/values.yaml) | **Open** |
| T6 | E | Abuse of the admin token (creates tenants) | Separate bearer token, required at install (chart refuses without it), stored in a Kubernetes Secret. Static, with no rotation or audit log. | [secret.yaml](../deploy/helm/sentinelflow/templates/secret.yaml) | Partial |

### TB2: Internal bus and database

| ID | STRIDE | Threat | Control | Evidence | Status |
|---|---|---|---|---|---|
| T7 | T, S | **A compromised scanner publishes a forged `policy.evaluated` (or another scanner's results), turning a FAIL into a PASS** | Three links, each enforced by a different layer: (1) **NATS least privilege**: one user per service, no anonymous access; scanners may publish only `scan.completed.<own type>`, only the policy engine may publish `policy.evaluated`, and per-service reply inboxes stop services reading or injecting into each other's JetStream replies. Only the gateway worker can create or change the stream. (2) A result whose payload claims a different target type than its subject is dropped. (3) The ingester rejects results whose target type differs from the scan's. CI attacks the running stack with a scanner's real credentials. | [nats.conf](../deploy/helm/sentinelflow/files/nats.conf), [bus.py](../libs/common/src/sentinelflow_common/bus.py), [ingest.py](../services/gateway/src/sentinelflow_gateway/ingest.py), [check_nats_permissions.sh](../scripts/check_nats_permissions.sh), [test_bus.py](../libs/common/tests/test_bus.py), [test_ingest.py](../services/gateway/tests/test_ingest.py) | Mitigated. Residual: a compromised scanner can still forge results **for its own target type** (e.g. the image scanner for image scans); it is trusted for those by design. |
| T8 | T | Lost or duplicated events change outcomes | Transactional outbox; `Nats-Msg-Id` dedup; ingester ignores results for scans already terminal | [test_outbox.py](../services/gateway/tests/test_outbox.py), [test_ingest.py](../services/gateway/tests/test_ingest.py) | Mitigated |
| T9 | T | Policy engine fails open (OPA down, undefined decision) → scan marked passing | Fail closed: retried, never marked passing without a decision; OPA output strictly validated | [test_engine.py](../services/policy-engine/tests/test_engine.py) | Mitigated |
| T10 | E | A compromised scanner reaches Postgres or OPA directly | Default-deny NetworkPolicies: only the gateway API, gateway worker, notifier and migration job reach Postgres; OPA port reachable only inside its pod. Verified by live TCP probes in CI. | [check_network_policies.sh](../scripts/check_network_policies.sh) | Mitigated |
| T11 | I | Sniffing in-cluster traffic (Postgres, NATS are plaintext) | Restricted by NetworkPolicy; no TLS between pods | – | Partial (needs mTLS/service mesh in production) |
| T12 | I | Database leak exposes webhook signing secrets | API keys are hashed, but webhook secrets must be usable for HMAC and are stored in plaintext | [models.py](../services/gateway/src/sentinelflow_gateway/models.py) | **Open** (encrypt at rest with a KMS-held key) |

### TB3: Scanners → untrusted content

| ID | STRIDE | Threat | Control | Evidence | Status |
|---|---|---|---|---|---|
| T13 | E, I | **SSRF**: scan `http://169.254.169.254/`, `localhost`, RFC 1918, via redirects or DNS rebinding | Guard enforced at the **connection layer**: every TCP connect (each redirect hop, the TLS probe) resolves the host, requires every address to be public, and connects to that exact IP. Ports limited to 80/443/8080/8443; proxies ignored. | [ssrf.py](../libs/common/src/sentinelflow_common/ssrf.py), [test_ssrf.py](../libs/common/tests/test_ssrf.py) (non-public ranges, names resolving to loopback), [test_probe.py](../services/scanner-api/tests/test_probe.py) (redirects re-checked). DNS rebinding is defeated by design (we connect to the validated IP); no dedicated test yet. | Mitigated |
| T14 | E | SSRF guard bypassed by an application bug | **Defence in depth**: the "internet" NetworkPolicy excludes private, link-local and CGNAT ranges, so the network drops it even if the code allows it. CI probes `169.254.169.254` from a scanner pod. | [networkpolicies.yaml](../deploy/helm/sentinelflow/templates/networkpolicies.yaml) | Mitigated |
| T15 | E | Malicious image or Dockerfile exploits Trivy or Hadolint | Scanners run non-root, read-only root FS, no capabilities, seccomp `RuntimeDefault`, no service-account token, no Docker socket; the Dockerfile scanner has no internet egress. Pod Security "restricted" is enforced on the namespace. | [components.yaml](../deploy/helm/sentinelflow/templates/components.yaml) | Mitigated (impact contained; see T7 for what a compromised scanner can still do) |
| T16 | D | Huge image or slow endpoint ties up a scanner | Scan timeouts (600 s image, bounded HTTP), findings capped at 500, memory limits per pod | [values.yaml](../deploy/helm/sentinelflow/values.yaml) | Mitigated |
| T17 | T | Tampered vulnerability database → missed CVEs (false PASS) | Trivy's DB is fetched from its official OCI registry over TLS; Trivy binary pinned by digest | [scanner-image Dockerfile](../services/scanner-image/Dockerfile) | Partial (DB signature not verified independently) |

### TB4: Notifier → tenant webhooks

| ID | STRIDE | Threat | Control | Evidence | Status |
|---|---|---|---|---|---|
| T18 | E | Webhook URL pointed at internal services (SSRF via alerts) | Same connection-level guard (`guarded_client`, redirects not followed); TLS verification on; non-http(s) and credential-bearing URLs rejected at config time | [notifier.py](../services/gateway/src/sentinelflow_gateway/notifier.py), [test_webhooks.py](../services/gateway/tests/test_webhooks.py) | Mitigated (no webhook-specific private-address test yet) |
| T19 | S, R | Forged or replayed alerts to a tenant | HMAC-SHA256 over timestamp + raw body; receivers reject timestamps older than 5 min; unique delivery ID for dedup; reference receiver | [receiver.py](../tools/webhook-receiver/receiver.py), [test_webhooks.py](../services/gateway/tests/test_webhooks.py) | Mitigated |
| T20 | D | Slow receivers exhaust the notifier or hold DB locks | Lease-based dispatch commits before sending; per-request timeouts; bounded retries with backoff | [notifier.py](../services/gateway/src/sentinelflow_gateway/notifier.py) | Mitigated |

### TB5: Supply chain

| ID | STRIDE | Threat | Control | Evidence | Status |
|---|---|---|---|---|---|
| T21 | T | Compromised GitHub Action or base image | Actions pinned to commit SHAs, base images to digests; Dependabot proposes bumps, which must pass the full pipeline | [ci.yml](../.github/workflows/ci.yml), [dependabot.yml](../.github/dependabot.yml) | Mitigated |
| T22 | T | Tampered image deployed | Keyless cosign signatures bound to `release.yml` in this repo; deploy verifies every signature and SBOM attestation, installs by digest, and fails if any pod runs a mutable tag | [release.yml](../.github/workflows/release.yml) | Mitigated in CI; Partial in clusters (no admission controller enforcing signatures) |
| T23 | T | Shipping known-vulnerable images | Trivy gate: an image is signed only if it has no fixable CRITICAL. The first run found and forced fixes for 4 critical CVEs in our own images. | [release.yml](../.github/workflows/release.yml) | Mitigated |
| T24 | I | Secrets committed to the repo | gitleaks in pre-commit and CI (full history); `detect-private-key` hook | [.pre-commit-config.yaml](../.pre-commit-config.yaml) | Mitigated |

## Open risks and planned work

**Fixed after the first review:** T7, the main false-PASS path. The first version of this
document found that any pod reaching NATS could publish any event, including a forged
`policy.evaluated`. It is now closed by NATS per-service permissions plus two payload
checks, and CI attacks it on every run (see T7).

Remaining, in priority order:

1. **T5: per-tenant rate limit and concurrent-scan quota** at the gateway.
2. **T12: encrypt webhook secrets at rest** (envelope encryption, key outside the database).
3. **T22: admission control.** Enforce cosign signatures in the cluster (Sigstore
   policy-controller or Kyverno), so unsigned images can't run even if deployed by hand.
4. **T11: mTLS between services** in production (service mesh or NATS/Postgres TLS).
5. **T6: admin token rotation and an audit log** of tenant creation.
6. **T7 residual:** sign scan results with per-scanner keys, so even a compromised scanner
   can't forge results without also stealing its key.

## Residual assumptions

- The Kubernetes CNI enforces NetworkPolicies (kind's kindnet, Calico and Cilium do; CI verifies
  enforcement on every run).
- Tenants trust SentinelFlow with their scan results; there is no end-to-end encryption of
  findings.
- Scanning is non-destructive (one `GET`, one TLS handshake), but tenants must only scan
  endpoints they're authorised to test (see the README's "Responsible use").
