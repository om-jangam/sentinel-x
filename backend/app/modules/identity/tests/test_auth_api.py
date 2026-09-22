from __future__ import annotations

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.core.audit.repository import list_audit_entries, verify_audit_chain
from app.core.container import Container

pytestmark = pytest.mark.usefixtures("seeded")


def _refresh_cookie(client: httpx.AsyncClient) -> str | None:
    return client.cookies.get("sx_refresh")


def _present_refresh_cookie(client: httpx.AsyncClient, value: str | None) -> None:
    """Replace the jar's refresh cookie (e.g. to replay an old token), avoiding duplicate-domain entries."""
    client.cookies.clear()
    client.cookies.set("sx_refresh", value or "", path="/api/v1/auth")


async def _audit_actions(container: Container, seeded: Seeded) -> list[str]:
    async with container.database.sessionmaker() as session:
        return [e.action for e in await list_audit_entries(session, seeded.org.id, limit=200)]


async def test_login_issues_access_token_and_hardened_refresh_cookie(client: httpx.AsyncClient, seeded: Seeded) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"email": seeded.admin_email.upper(), "password": seeded.admin_password}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 600

    cookie_header = response.headers["set-cookie"].lower()
    for attribute in ("httponly", "secure", "samesite=strict", "path=/api/v1/auth"):
        assert attribute in cookie_header
    assert "refresh" not in body, "refresh token must never be exposed to JavaScript"

    me = await client.get("/api/v1/me", headers=bearer(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == seeded.admin_email
    assert "admin" in me.json()["roles"]
    assert "user:manage" in me.json()["permissions"]


async def test_login_failures_are_uniform_and_audited(
    client: httpx.AsyncClient, seeded: Seeded, container: Container
) -> None:
    wrong_password = await client.post(
        "/api/v1/auth/login", json={"email": seeded.admin_email, "password": "wrong-password-123"}
    )
    unknown_user = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong-password-123"}
    )
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"]
    assert wrong_password.headers["content-type"] == "application/problem+json"
    assert "auth.login_failed" in await _audit_actions(container, seeded)


async def test_login_is_rate_limited_per_account(client: httpx.AsyncClient, seeded: Seeded) -> None:
    statuses = [
        (
            await client.post("/api/v1/auth/login", json={"email": seeded.admin_email, "password": "nope-nope-nope"})
        ).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
    blocked = await client.post(
        "/api/v1/auth/login", json={"email": seeded.admin_email, "password": seeded.admin_password}
    )
    assert blocked.status_code == 429, "even the right password is refused while limited"
    assert int(blocked.headers["retry-after"]) >= 1


async def test_validation_errors_never_echo_the_password(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "x" * 500})
    assert response.status_code == 422
    assert "xxxx" not in response.text


async def test_refresh_rotates_the_token(client: httpx.AsyncClient, seeded: Seeded) -> None:
    await login(client, seeded.admin_email, seeded.admin_password)
    first = _refresh_cookie(client)

    response = await client.post("/api/v1/auth/refresh")
    assert response.status_code == 200
    second = _refresh_cookie(client)
    assert second
    assert second != first
    assert (await client.get("/api/v1/me", headers=bearer(response.json()["access_token"]))).status_code == 200


async def test_refresh_token_reuse_revokes_the_whole_family(
    client: httpx.AsyncClient, seeded: Seeded, container: Container
) -> None:
    await login(client, seeded.admin_email, seeded.admin_password)
    stolen = _refresh_cookie(client)
    assert stolen

    assert (await client.post("/api/v1/auth/refresh")).status_code == 200  # legitimate rotation
    current = _refresh_cookie(client)

    # Attacker replays the spent token.
    _present_refresh_cookie(client, stolen)
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401
    assert "reuse" in replay.json()["detail"]

    # The legitimate user's newer token died with the family.
    _present_refresh_cookie(client, current)
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401
    assert "auth.refresh_token_reuse_detected" in await _audit_actions(container, seeded)


async def test_refresh_without_cookie_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/auth/refresh")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_logout_revokes_access_and_refresh(client: httpx.AsyncClient, seeded: Seeded) -> None:
    token = await login(client, seeded.admin_email, seeded.admin_password)
    refresh = _refresh_cookie(client)

    response = await client.post("/api/v1/auth/logout", headers=bearer(token))
    assert response.status_code == 204

    assert (await client.get("/api/v1/me", headers=bearer(token))).status_code == 401
    _present_refresh_cookie(client, refresh)
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401


async def test_logout_works_with_only_the_refresh_cookie(client: httpx.AsyncClient, seeded: Seeded) -> None:
    await login(client, seeded.admin_email, seeded.admin_password)
    refresh = _refresh_cookie(client)
    assert (await client.post("/api/v1/auth/logout", headers=bearer("expired.or.garbage"))).status_code == 204
    _present_refresh_cookie(client, refresh)
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer not-a-jwt"}, {"Authorization": "Basic YTpi"}],
)
async def test_protected_endpoints_require_a_valid_token(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
    response = await client.get("/api/v1/me", headers=headers)
    assert response.status_code in (401, 403)
    assert response.headers["content-type"] == "application/problem+json"


async def test_jwks_publishes_the_signing_key(client: httpx.AsyncClient, container: Container) -> None:
    keys = (await client.get("/.well-known/jwks.json")).json()["keys"]
    assert [k["kid"] for k in keys] == [container.keyring.signing_kid]
    assert all(set(k) == {"kty", "use", "alg", "kid", "n", "e"} for k in keys), "no private members"


async def test_auth_activity_keeps_the_audit_chain_valid(
    client: httpx.AsyncClient, seeded: Seeded, container: Container
) -> None:
    token = await login(client, seeded.admin_email, seeded.admin_password)
    await client.post("/api/v1/auth/refresh")
    await client.post("/api/v1/auth/logout", headers=bearer(token))
    async with container.database.sessionmaker() as session:
        result = await verify_audit_chain(session, seeded.org.id)
    assert result.valid
    assert {"auth.login_succeeded", "auth.logout"} <= set(await _audit_actions(container, seeded))


async def test_changing_your_password_signs_out_every_other_session(
    client: httpx.AsyncClient, seeded: Seeded, container: Container
) -> None:
    # Two sessions: another browser (whose cookie we keep aside), then this one.
    await login(client, seeded.admin_email, seeded.admin_password)
    other_browser = _refresh_cookie(client)
    token = await login(client, seeded.admin_email, seeded.admin_password)
    new_password = "a-brand-new-passphrase-7"

    changed = await client.post(
        "/api/v1/auth/password",
        headers=bearer(token),
        json={"current_password": seeded.admin_password, "new_password": new_password},
    )
    assert changed.status_code == 200, changed.text
    fresh = changed.json()["access_token"]
    assert (await client.get("/api/v1/me", headers=bearer(fresh))).status_code == 200, "this browser stays in"
    assert (await client.get("/api/v1/me", headers=bearer(token))).status_code == 401, "the old token is blocked"
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200, "the new refresh cookie works"

    _present_refresh_cookie(client, other_browser)
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401, "the other browser is signed out"

    old = await client.post("/api/v1/auth/login", json={"email": seeded.admin_email, "password": seeded.admin_password})
    assert old.status_code == 401
    assert await login(client, seeded.admin_email, new_password)
    assert "auth.password_changed" in await _audit_actions(container, seeded)


async def test_a_password_change_needs_the_current_password_and_a_good_new_one(
    client: httpx.AsyncClient, seeded: Seeded, container: Container
) -> None:
    token = await login(client, seeded.admin_email, seeded.admin_password)

    async def change(current: str, new: str) -> httpx.Response:
        return await client.post(
            "/api/v1/auth/password", headers=bearer(token), json={"current_password": current, "new_password": new}
        )

    wrong = await change("not-my-password-at-all", "a-brand-new-passphrase-7")
    assert wrong.status_code == 422, "a wrong current password must not look like an expired session"
    assert "incorrect" in wrong.text
    assert seeded.admin_password not in wrong.text
    assert (await change(seeded.admin_password, "short")).status_code == 422
    assert (await change(seeded.admin_password, seeded.admin_password)).status_code == 422
    assert "auth.password_change_failed" in await _audit_actions(container, seeded)
    assert (
        await client.post("/api/v1/auth/password", json={"current_password": "x", "new_password": "y"})
    ).status_code == 401


async def test_password_change_guesses_are_rate_limited(client: httpx.AsyncClient, seeded: Seeded) -> None:
    token = await login(client, seeded.admin_email, seeded.admin_password)
    statuses = [
        (
            await client.post(
                "/api/v1/auth/password",
                headers=bearer(token),
                json={"current_password": f"guess-number-{i}", "new_password": "a-brand-new-passphrase-7"},
            )
        ).status_code
        for i in range(7)
    ]
    assert statuses[:5] == [422] * 5
    assert statuses[5:] == [429, 429], "the settings fixture allows 5 attempts per window"
