# ADR-0010 · Auth stack: PyJWT + argon2 + custom JWT

**Status:** Accepted · **Date:** 2026-07

## Context

A security product's own auth must be exemplary. Several once-standard libraries are now stale traps:
**python-jose** is effectively abandoned and removed from FastAPI docs; **passlib** is unmaintained;
**fastapi-users** development is slow. Getting this wrong in a *security* portfolio project is
disqualifying.

## Decision

- **JWT with PyJWT**; access tokens signed **RS256** (asymmetric — verifiers never hold the signing
  key), short TTL (~10 min), carrying `sub/org_id/roles/jti/exp`.
- **Refresh tokens** opaque + random, stored **hashed**, delivered as `HttpOnly; Secure;
  SameSite=Strict` cookies, **rotated every use with reuse detection** (replay invalidates the token
  family).
- **Password hashing** argon2id via **pwdlib**.
- **MFA** TOTP for privileged roles.
- **Custom JWT flow** (own it) or **external OIDC** (Keycloak/Authentik) for enterprise SSO — not
  `fastapi-users`.
- Signing keys in a secrets manager, rotated via JWKS with overlapping validity.

## Alternatives considered

- **python-jose / passlib** — rejected: abandoned/stale.
- **fastapi-users** — rejected for a security-critical flow: half-maintained; prefer owning the flow
  or delegating to a real IdP.
- **Session cookies only** — rejected: WS/agent/service principals need bearer tokens; JWT+refresh
  fits better and enables stateless verification.

## Consequences

- Modern, defensible auth; immediate revocation via `jti` blocklist; theft-detection via refresh
  rotation.
- We own more of the flow (mitigated by well-trodden PyJWT patterns and optional OIDC delegation).
