# 07 · Security Architecture

*Reference design, July 2026.*

> **Status — partially current.** **Implemented:**
> - §2: RS256 access tokens, rotating refresh tokens with reuse detection, `jti` revocation, JWKS key
>   rotation. *Not built:* MFA, breached-password checks, OIDC.
> - §3: RBAC and `org_id` scoping, plus `event:*`, `source:*` and `ingest:write`; `incident_responder`
>   no longer approves containment. *Not built:* field-level authorisation.
> - §4: the audit chain.
> - §6: stores on an internal network, CORS allowlist, CSP. *Not built:* TLS termination, mTLS, a secrets
>   manager.
> - §7: rate limiting, via an in-house Redis fixed-window limiter rather than `fastapi-limiter`.
>
> **Not adopted** ([ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md)): §5 file upload and
> malware analysis, and every control for agents, MCP, Neo4j and model-gateway budgets. AI safety is
> specified in [04](04-ai-investigation-assistant.md). As built: [architecture.md](architecture.md) §7.

A security product must be exemplary about its own security. This document specifies the platform's
defensive posture. It maps to the requested controls (JWT, RBAC, audit logs, secure file upload,
HTTPS, rate limiting) and extends them to a coherent whole.

---

## 1. Threat model (abridged, STRIDE-oriented)

| Asset | Primary threats | Principal mitigations |
|-------|-----------------|-----------------------|
| Analyst credentials / sessions | Credential theft, session hijack, phishing | Argon2id hashing, MFA (TOTP), short-lived access JWT + rotating refresh, httpOnly/SameSite cookies |
| Security telemetry & incidents | Unauthorised read, tampering, exfiltration | RBAC + `org_id` isolation, field-level authz, tamper-evident audit, TLS in transit / encryption at rest |
| Detection rules & config | Malicious rule disable, backdoored rule | RBAC on rule lifecycle, mandatory audit, draft→test→promote gate, change review |
| The AI agents | **Prompt injection**, tool abuse, data exfil via LLM | Untrusted-by-default tool output, curated tool descriptions, output-as-data, egress allowlist, human gates on actions |
| Uploaded files (malware samples, emails) | Sandbox escape, RCE, storage poisoning | Isolated analysis worker, no execution in-process, size/type limits, quarantined storage, AV/YARA pre-scan |
| Platform infrastructure | Lateral movement, secret theft | Network segmentation, least-privilege service accounts, secrets manager, no secrets in images |
| Model provider channel | Sensitive-data leakage to external API | Local-first routing, PII redaction, per-org egress policy, opt-in external inference |

## 2. Authentication

- **Password auth**: Argon2id via `pwdlib`; configurable work factors; breached-password check
  against a local k-anonymity list on set/reset.
- **MFA**: TOTP (RFC 6238) mandatory for privileged roles; WebAuthn/passkeys on the roadmap.
- **Tokens** (see [ADR-0010](adr/ADR-0010-auth-stack.md)):
  - **Access JWT** — short TTL (~10 min), signed **RS256** (asymmetric, so verifiers never hold the
    signing key), carries `sub`, `org_id`, `roles`, `jti`, `exp`.
  - **Refresh token** — opaque, random, stored **hashed** server-side, delivered as
    `HttpOnly; Secure; SameSite=Strict` cookie; **rotated on every use** with reuse detection
    (a replayed old refresh invalidates the whole family — theft signal).
  - **Revocation** — `jti` blocklist in Redis for immediate access-token kill; refresh family
    invalidation on logout/compromise.
- **External IdP option**: OIDC (Keycloak/Authentik) for SSO — avoids owning the full identity
  lifecycle in enterprise deployments. Custom JWT chosen over `fastapi-users` (half-maintained) for
  a security-critical flow.
- **Key management**: signing keys in the secrets manager, rotated on a schedule with a JWKS
  endpoint and overlapping key validity so rotation causes no downtime.

## 3. Authorisation — RBAC

- **Model**: users → roles → permissions; permissions are `resource:action` strings
  (`incident:resolve`, `rule:promote`, `audit:read`, `intel:sync`, `user:manage`).
- **Default roles**: `viewer`, `analyst`, `senior_analyst`, `incident_responder`, `detection_engineer`,
  `admin`, plus a locked-down `service` role for machine principals (agents, integrations).
- **Enforcement** in the **application layer** (not just the router) via a policy dependency —
  `require("incident:resolve")` — so authz is close to the use-case and testable, and can't be
  bypassed by an alternate entry point (worker, MCP).
- **Field-level authz**: response schemas strip fields the principal can't see (e.g. raw enrichment,
  approver identity) — enforced in the serialisation layer.
- **Tenant isolation**: `org_id` is a non-optional filter on every query (repository base class
  injects it); cross-org access is structurally impossible, not policy-dependent.
- **Agent principals**: agents act under a scoped `service` identity with *least* privilege — they
  can read telemetry and enrich, but **cannot** self-approve actions or change RBAC. This closes the
  "compromised agent escalates itself" path.
- **Roadmap**: ABAC/ReBAC (attribute/relationship policies) for finer-grained sharing if
  multi-tenant SaaS is pursued.

## 4. Audit logging

Tamper-evident, hash-chained, transaction-coupled — full design in
[§05 Database Design](05-database-design.md) §4. Audit scope explicitly includes **every AI agent
decision, tool call, and human approval**, because "why did the system act" must be answerable to a
regulator. Audit is read-only via API (`audit:read`) and never deletable within retention.

## 5. Secure file upload (malware samples, emails, KB docs)

The most dangerous input surface — a *security* product invites hostile files by design.

1. **Pre-acceptance**: size cap, declared vs sniffed MIME check (`python-magic`), extension policy,
   per-user quota, `Idempotency-Key`.
2. **Quarantine storage**: written to a dedicated, non-executable, private object-storage bucket with
   a random key; never served from a web-accessible path; original filename never used on disk.
3. **Isolated analysis**: processing happens in a **separate hardened worker** (seccomp/AppArmor,
   read-only FS, no outbound network except allowlisted intel APIs, resource limits, non-root). The
   API process never parses hostile files.
4. **No in-process execution**: static analysis only (YARA-X, pefile/LIEF, oletools, email parsing);
   dynamic detonation is delegated to an **external** sandbox (CAPEv2/Tria.ge) over its API — never
   run on platform hosts.
5. **Content Disarm**: generated reports and extracted artifacts are sanitised; downloads carry
   `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` and are served from a
   separate origin/path.
6. **AV/known-bad pre-scan** and hash lookup before deep analysis to fail fast on known samples.

## 6. Transport & network security

- **HTTPS/TLS 1.3** terminated at the ingress (reverse proxy / K8s ingress); internal service traffic
  over mTLS in the cluster (service mesh optional).
- **HSTS**, secure cookies, strict **CORS allowlist**, and a strong **CSP** on the frontend.
- **Network segmentation**: data stores on a private network, never internet-exposed; `/metrics`
  bound to the internal network; egress from the agent/analysis tier restricted to an **allowlist**
  of intel/model endpoints (defeats data-exfil-via-tool and SSRF).
- **Secrets**: from a secrets manager (K8s Secrets + sealed-secrets / Vault); never in images, env
  files in git, or logs; `gitleaks` in CI blocks committed secrets.

## 7. Rate limiting & abuse protection

- **Redis-backed** (`fastapi-limiter`), per-principal and per-IP, with stricter limits on auth,
  enrichment (protects fragile free-tier APIs), and upload endpoints.
- **Cost limits** at the model gateway (per-org token budgets) prevent an abusive/compromised
  investigation from running up unbounded LLM cost.
- **Request-size** and **query-complexity** limits (constrained DSL) prevent resource-exhaustion DoS
  against OpenSearch/Neo4j.

## 8. Application-security controls

- **Input validation** everywhere via Pydantic; **no raw backend query pass-through** — client
  filters are translated server-side into constrained OpenSearch/Neo4j queries (prevents injection
  and expensive queries).
- **ORM parameterisation** (SQLAlchemy) — no string-built SQL.
- **Output encoding** and React's default escaping; CSP as defence-in-depth against XSS.
- **CSRF**: refresh cookie is `SameSite=Strict`; state-changing requests require the bearer header
  (not cookie-auth), so CSRF is structurally mitigated.
- **Dependency & container hygiene**: `trivy`, `bandit`, `semgrep`, `pip-audit`/Dependabot, SBOM in
  CI (see [§08](08-deployment-and-cicd.md)).

## 9. AI-specific security (the novel surface)

Prompt injection is the #1 documented agent/MCP risk. Controls:

- **Untrusted-by-default**: all tool results, enrichment responses, email/file contents are treated
  as adversarial data, provenance-tagged, and never interpreted as instructions.
- **Curated tool descriptions**: MCP tool metadata is static and reviewed — never model-generated
  (a known injection channel).
- **Output-as-data**: an agent's *proposed* action is a structured proposal; it only takes effect
  through the deterministic execution path behind a **human approval gate**. A model cannot directly
  cause a state change.
- **Egress allowlist** from the agent tier — even a fully hijacked agent cannot phone home.
- **PII redaction** before any external-API inference; local-first routing keeps sensitive data
  on-prem by default.
- **Least-privilege agent identity** (§3) — an agent can't approve its own actions or touch RBAC.
- **Golden-set evaluation + groundedness checks** ([§04](04-ai-investigation-assistant.md) §8) catch
  regressions and unsupported conclusions before they reach analysts.

## 10. Compliance & data governance posture

- **Data minimisation**: index only needed OCSF fields; PII tagging on fields enables redaction and
  right-to-erasure workflows.
- **Retention & legal hold**: enforced per [§05](05-database-design.md) §8; soft-delete-first with
  audited hard-delete.
- **TLP handling**: threat-intel Traffic Light Protocol tags propagate to storage filters and
  report redaction so restricted intel isn't over-shared.
- **Alignment**: designed against **OWASP ASVS**, **OWASP Top 10** and **OWASP LLM Top 10**, with an
  eye to SOC 2 / ISO 27001 control mapping (audit, access control, change management) — appropriate
  for a product that would itself be audited.
