"""User and role administration: RBAC enforcement, safety guards, audit coverage."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.core.audit.repository import list_audit_entries
from app.core.container import Container

PASSWORD = "a-very-long-passphrase-42"


async def _create_user(
    client: httpx.AsyncClient, token: str, email: str, roles: list[str] | None = None
) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": email, "full_name": "Test User", "password": PASSWORD, "roles": roles or []},
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def test_admin_creates_user_who_can_log_in(client: httpx.AsyncClient, admin_token: str) -> None:
    user = await _create_user(client, admin_token, "Analyst@Example.com", ["analyst"])
    assert user["email"] == "analyst@example.com"
    assert user["roles"] == ["analyst"]
    assert "hashed_password" not in user

    token = await login(client, "analyst@example.com", PASSWORD)
    me = (await client.get("/api/v1/me", headers=bearer(token))).json()
    assert me["permissions"] == [
        "event:read",
        "finding:read",
        "incident:read",
        "incident:update",
        "intel:read",
        "platform:read",
        "rule:read",
        "source:read",
    ]


async def test_duplicate_email_conflicts(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    response = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": seeded.admin_email, "full_name": "Dup", "password": PASSWORD},
    )
    assert response.status_code == 409


async def test_weak_password_and_unknown_role_are_rejected(client: httpx.AsyncClient, admin_token: str) -> None:
    weak = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": "w@example.com", "full_name": "W", "password": "short"},
    )
    assert weak.status_code == 422
    unknown = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": "u@example.com", "full_name": "U", "password": PASSWORD, "roles": ["god_mode"]},
    )
    assert unknown.status_code == 422
    assert "god_mode" in unknown.text


async def test_over_posting_is_rejected(client: httpx.AsyncClient, admin_token: str) -> None:
    response = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": "o@example.com", "full_name": "O", "password": PASSWORD, "is_superuser": True},
    )
    assert response.status_code == 422


async def test_non_admin_is_forbidden(client: httpx.AsyncClient, admin_token: str) -> None:
    await _create_user(client, admin_token, "viewer@example.com", ["viewer"])
    token = await login(client, "viewer@example.com", PASSWORD)
    for method, path in [("GET", "/api/v1/users"), ("POST", "/api/v1/roles"), ("GET", "/api/v1/audit")]:
        response = await client.request(method, path, headers=bearer(token), json={})
        assert response.status_code == 403, path
        assert response.json()["type"].endswith("/insufficient-permission")


async def test_user_listing_paginates(client: httpx.AsyncClient, admin_token: str) -> None:
    for i in range(3):
        await _create_user(client, admin_token, f"user{i}@example.com")
    first = (await client.get("/api/v1/users?limit=2", headers=bearer(admin_token))).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]
    second = (
        await client.get(f"/api/v1/users?limit=2&cursor={first['next_cursor']}", headers=bearer(admin_token))
    ).json()
    assert len(second["items"]) == 2
    assert second["next_cursor"] is None
    ids = [u["id"] for u in first["items"] + second["items"]]
    assert len(set(ids)) == 4
    bad = await client.get("/api/v1/users?cursor=%%%", headers=bearer(admin_token))
    assert bad.status_code == 422


async def test_role_change_takes_effect_immediately(client: httpx.AsyncClient, admin_token: str) -> None:
    user = await _create_user(client, admin_token, "promote@example.com", ["analyst"])
    token = await login(client, "promote@example.com", PASSWORD)
    assert (await client.get("/api/v1/audit", headers=bearer(token))).status_code == 403

    response = await client.put(
        f"/api/v1/users/{user['id']}/roles", headers=bearer(admin_token), json={"roles": ["senior_analyst"]}
    )
    assert response.status_code == 200
    # Same access token, no re-login: permissions are resolved live.
    assert (await client.get("/api/v1/audit", headers=bearer(token))).status_code == 200


async def test_deactivation_locks_out_immediately(client: httpx.AsyncClient, admin_token: str) -> None:
    user = await _create_user(client, admin_token, "leaver@example.com", ["analyst"])
    token = await login(client, "leaver@example.com", PASSWORD)

    assert (await client.delete(f"/api/v1/users/{user['id']}", headers=bearer(admin_token))).status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(token))).status_code == 401
    relogin = await client.post("/api/v1/auth/login", json={"email": "leaver@example.com", "password": PASSWORD})
    assert relogin.status_code == 401


async def test_password_reset_revokes_existing_sessions(client: httpx.AsyncClient, admin_token: str) -> None:
    user = await _create_user(client, admin_token, "reset@example.com")
    await login(client, "reset@example.com", PASSWORD)
    stale_refresh = client.cookies.get("sx_refresh")

    response = await client.patch(
        f"/api/v1/users/{user['id']}", headers=bearer(admin_token), json={"password": "another-long-passphrase-7"}
    )
    assert response.status_code == 200
    client.cookies.clear()
    client.cookies.set("sx_refresh", stale_refresh or "", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401
    await login(client, "reset@example.com", "another-long-passphrase-7")


async def test_admin_cannot_lock_the_org_out(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    admin_id = seeded.admin.id
    self_deactivate = await client.patch(
        f"/api/v1/users/{admin_id}", headers=bearer(admin_token), json={"is_active": False}
    )
    assert self_deactivate.status_code == 409

    demote_last_admin = await client.put(
        f"/api/v1/users/{admin_id}/roles", headers=bearer(admin_token), json={"roles": ["viewer"]}
    )
    assert demote_last_admin.status_code == 409
    me = (await client.get("/api/v1/me", headers=bearer(admin_token))).json()
    assert "admin" in me["roles"], "rejected change must be rolled back"


async def test_second_admin_allows_demotion(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _create_user(client, admin_token, "admin2@example.com", ["admin"])
    response = await client.put(
        f"/api/v1/users/{seeded.admin.id}/roles", headers=bearer(admin_token), json={"roles": ["viewer"]}
    )
    assert response.status_code == 200


async def test_service_role_cannot_hold_privileged_permissions(client: httpx.AsyncClient, admin_token: str) -> None:
    user = await _create_user(client, admin_token, "agent@example.com", ["service"])
    response = await client.put(
        f"/api/v1/users/{user['id']}/roles", headers=bearer(admin_token), json={"roles": ["service", "admin"]}
    )
    assert response.status_code == 422

    role = (
        await client.post(
            "/api/v1/roles",
            headers=bearer(admin_token),
            json={"name": "agent_extras", "permissions": ["audit:read"]},
        )
    ).json()
    assign = await client.put(
        f"/api/v1/users/{user['id']}/roles", headers=bearer(admin_token), json={"roles": ["service", "agent_extras"]}
    )
    assert assign.status_code == 200
    escalate = await client.patch(
        f"/api/v1/roles/{role['id']}", headers=bearer(admin_token), json={"permissions": ["role:manage"]}
    )
    assert escalate.status_code == 422


async def test_custom_role_lifecycle(client: httpx.AsyncClient, admin_token: str) -> None:
    created = await client.post(
        "/api/v1/roles",
        headers=bearer(admin_token),
        json={"name": "soc_auditor", "description": "Reads audit", "permissions": ["audit:read", "platform:read"]},
    )
    assert created.status_code == 201
    role = created.json()
    assert role["permissions"] == ["audit:read", "platform:read"]
    assert not role["is_system"]

    updated = await client.patch(
        f"/api/v1/roles/{role['id']}", headers=bearer(admin_token), json={"permissions": ["platform:read"]}
    )
    assert updated.json()["permissions"] == ["platform:read"]

    assert (
        await client.post("/api/v1/roles", headers=bearer(admin_token), json={"name": "soc_auditor"})
    ).status_code == 409
    assert (await client.post("/api/v1/roles", headers=bearer(admin_token), json={"name": "admin"})).status_code == 409
    unknown = await client.post(
        "/api/v1/roles", headers=bearer(admin_token), json={"name": "bad_perm", "permissions": ["nuke:all"]}
    )
    assert unknown.status_code == 422


async def test_system_roles_are_immutable(client: httpx.AsyncClient, admin_token: str) -> None:
    roles = (await client.get("/api/v1/roles", headers=bearer(admin_token))).json()
    assert {r["name"] for r in roles} >= {"viewer", "analyst", "admin", "service"}
    admin_role = next(r for r in roles if r["name"] == "admin")
    response = await client.patch(
        f"/api/v1/roles/{admin_role['id']}", headers=bearer(admin_token), json={"permissions": []}
    )
    assert response.status_code == 409


async def test_permissions_catalogue(client: httpx.AsyncClient, admin_token: str) -> None:
    permissions = (await client.get("/api/v1/permissions", headers=bearer(admin_token))).json()
    assert {"name": "audit:read", "description": "Read the audit log and verify its integrity"} in permissions


async def test_admin_actions_are_audited_without_secrets(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded, container: Container
) -> None:
    user = await _create_user(client, admin_token, "audited@example.com", ["analyst"])
    await client.patch(
        f"/api/v1/users/{user['id']}", headers=bearer(admin_token), json={"password": "rotated-passphrase-99"}
    )

    async with container.database.sessionmaker() as session:
        entries = await list_audit_entries(session, seeded.org.id, limit=100, resource_type="user")
    by_action = {e.action: e for e in entries if e.resource_id == user["id"]}
    assert by_action["user.created"].actor_id == seeded.admin.id
    assert by_action["user.updated"].after is not None
    assert by_action["user.updated"].after["password_changed"] is True
    serialized = str([(e.before, e.after, e.context) for e in entries])
    assert PASSWORD not in serialized
    assert "argon2" not in serialized


@pytest.mark.parametrize("path", ["/api/v1/users/not-a-uuid", "/api/v1/users/00000000-0000-7000-8000-000000000000"])
async def test_missing_users(client: httpx.AsyncClient, admin_token: str, path: str) -> None:
    response = await client.get(path, headers=bearer(admin_token))
    assert response.status_code in (404, 422)
