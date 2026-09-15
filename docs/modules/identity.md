# Module · `identity`

*Phase 0 · authentication, users, roles, RBAC* — implements [§07](../07-security-architecture.md) §2–3
and [ADR-0010](../adr/ADR-0010-auth-stack.md).

## Layout

| Layer | Contents |
|-------|----------|
| `domain/` | `User`, `Role`, `Org`, `RefreshToken` entities; repository **ports**; credential and naming policies |
| `application/` | `AuthService` (login / refresh / logout), `UserAdminService`, `RoleAdminService`, RBAC guards, idempotent bootstrap |
| `infrastructure/` | SQLAlchemy models + repositories, unit of work, `SqlPrincipalLoader` |
| `interface/` | FastAPI routers and Create / Update / Read schemas |

## Authentication flow

1. **Login** `POST /api/v1/auth/login` — rate limited per account (`login_rate_limit`) and per IP (5×).
   Unknown accounts burn an equal argon2id verification so account existence can't be timed; all
   failures return the same message. Success and failure are audited.
2. The response carries a short-lived **RS256 access JWT** (`typ: at+jwt`, `kid` = RFC 7638 thumbprint)
   and sets an opaque **refresh token** cookie: `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`.
   Only the refresh token's SHA-256 hash is stored.
3. **Refresh** `POST /api/v1/auth/refresh` rotates the token. Tokens from one login share a
   `family_id`; presenting a spent token — or losing the atomic `mark_used` race — **revokes the
   whole family** and writes `auth.refresh_token_reuse_detected` to the audit log.
4. **Logout** revokes the refresh family and blocklists the access token's `jti` until it expires
   (Redis in production). It works with only the refresh cookie, so expired sessions can still sign out.
5. `GET /.well-known/jwks.json` publishes verification keys. Rotation: `sentinelx generate-keys --force`
   keeps the previous public key for `SENTINELX_JWT_PREVIOUS_PUBLIC_KEY_FILE`.

## Authorisation

- Permissions are `resource:action` strings defined in `core/security/permissions.py`; `sentinelx seed`
  syncs them and reconciles the seven **system roles** to their code definition on every run.
- Each request resolves the principal's roles and permissions **from the database**, so role changes
  and deactivation take effect immediately rather than when a token expires.
- Checks run at the route (`require_permission`) **and** inside every use-case (`Principal.require`),
  so a future worker or MCP entry point cannot bypass them.
- Every query is scoped by `org_id`; another org's user is indistinguishable from a missing one (404).

### Safety invariants

| Guard | Why |
|-------|-----|
| An org must keep ≥ 1 active user with `user:manage` **and** `role:manage` | No change can lock administrators out (checked on the would-be state, then rolled back) |
| Admins can't deactivate themselves | Same |
| System roles are immutable via the API | Platform-defined least privilege can't drift |
| The `service` role can never be combined with, or gain, `user:manage` / `role:manage` | A compromised agent principal can't escalate itself (§07 §3) |
| Password change or deactivation revokes every refresh token for the user | Credential rotation ends existing sessions |

## API

| Method & path | Permission |
|---------------|-----------|
| `POST /api/v1/auth/login` · `/refresh` · `/logout` | — |
| `GET /api/v1/me` | authenticated |
| `GET /api/v1/users` (cursor-paginated) · `GET /api/v1/users/{id}` | `user:read` |
| `POST /api/v1/users` · `PATCH /api/v1/users/{id}` · `DELETE /api/v1/users/{id}` (deactivate) · `PUT /api/v1/users/{id}/roles` | `user:manage` |
| `GET /api/v1/roles` · `GET /api/v1/permissions` | `role:read` |
| `POST /api/v1/roles` · `PATCH /api/v1/roles/{id}` | `role:manage` |

Deviation from §06: role assignment is `PUT /users/{id}/roles` (replace the full set), because the
operation is idempotent replacement rather than appending.

## Audit actions

`auth.login_succeeded`, `auth.login_failed`, `auth.logout`, `auth.refresh_token_reuse_detected`,
`user.created`, `user.updated` (records `password_changed`, never the password), `user.roles_changed`,
`role.created`, `role.updated`, `role.system_synced`, `org.created`.

## Deferred (tracked, not stubbed)

- **TOTP MFA** for privileged roles and `POST /auth/mfa/verify`.
- **Breached-password** check against a local k-anonymity list.
- **OIDC** delegation (Keycloak/Authentik) for enterprise SSO.
