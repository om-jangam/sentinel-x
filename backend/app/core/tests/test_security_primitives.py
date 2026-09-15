from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.security.keys import KeyRing, generate_private_key, jwk_thumbprint
from app.core.security.passwords import PasswordHasher
from app.core.security.principal import Principal
from app.core.security.tokens import ACCESS_TOKEN_TYPE, AccessTokenService, hash_opaque_token


@pytest.fixture(scope="module")
def keyring() -> KeyRing:
    return KeyRing.build(generate_private_key(2048))


def _service(keyring: KeyRing, **kwargs: object) -> AccessTokenService:
    options: dict[str, object] = {"issuer": "sx", "audience": "sx-api", "ttl_seconds": 600}
    options.update(kwargs)
    return AccessTokenService(keyring, **options)  # type: ignore[arg-type]


def test_access_token_round_trip(keyring: KeyRing) -> None:
    service = _service(keyring)
    user_id, org_id = uuid4(), uuid4()
    issued = service.issue(user_id=user_id, org_id=org_id, roles=("admin",))
    claims = service.verify(issued.token)
    assert claims.subject == user_id
    assert claims.org_id == org_id
    assert claims.roles == ("admin",)
    assert claims.jti == issued.jti
    header = jwt.get_unverified_header(issued.token)
    assert header["alg"] == "RS256"
    assert header["typ"] == ACCESS_TOKEN_TYPE
    assert header["kid"] == keyring.signing_kid


def test_expired_token_is_rejected(keyring: KeyRing) -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    token = _service(keyring, clock=lambda: past).issue(user_id=uuid4(), org_id=uuid4(), roles=()).token
    with pytest.raises(AuthenticationError, match="expired"):
        _service(keyring).verify(token)


def test_token_from_unknown_key_is_rejected(keyring: KeyRing) -> None:
    other = KeyRing.build(generate_private_key(2048))
    token = _service(other).issue(user_id=uuid4(), org_id=uuid4(), roles=()).token
    with pytest.raises(AuthenticationError):
        _service(keyring).verify(token)


def test_wrong_audience_is_rejected(keyring: KeyRing) -> None:
    token = _service(keyring, audience="another-api").issue(user_id=uuid4(), org_id=uuid4(), roles=()).token
    with pytest.raises(AuthenticationError):
        _service(keyring).verify(token)


def test_algorithm_confusion_hs256_with_public_key_is_rejected(keyring: KeyRing) -> None:
    forged = jwt.encode(
        {"sub": str(uuid4()), "org_id": str(uuid4()), "jti": "x", "iat": 0, "nbf": 0, "exp": 9999999999},
        "an-attacker-chosen-hmac-secret-of-sufficient-length",
        algorithm="HS256",
        headers={"kid": keyring.signing_kid, "typ": ACCESS_TOKEN_TYPE},
    )
    with pytest.raises(AuthenticationError):
        _service(keyring).verify(forged)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "Bearer x"])
def test_garbage_tokens_are_rejected(keyring: KeyRing, garbage: str) -> None:
    with pytest.raises(AuthenticationError):
        _service(keyring).verify(garbage)


def test_rotation_keeps_previous_key_verifiable() -> None:
    old = generate_private_key(2048)
    old_ring = KeyRing.build(old)
    token = _service(old_ring).issue(user_id=uuid4(), org_id=uuid4(), roles=()).token

    rotated = KeyRing.build(generate_private_key(2048), previous_public_keys=[old.public_key()])
    assert rotated.signing_kid != old_ring.signing_kid
    assert _service(rotated).verify(token)
    assert {k["kid"] for k in rotated.jwks()["keys"]} == {rotated.signing_kid, jwk_thumbprint(old.public_key())}


def test_password_hashing_verifies_and_rejects() -> None:
    hasher = PasswordHasher(time_cost=1, memory_cost_kib=64, parallelism=1)
    hashed = hasher.hash("a long passphrase!")
    assert hashed.startswith("$argon2id$")
    assert hasher.verify("a long passphrase!", hashed) == (True, None)
    assert hasher.verify("wrong", hashed)[0] is False
    assert hasher.verify("anything", "not-a-hash") == (False, None)


def test_password_rehash_when_work_factor_increases() -> None:
    weak = PasswordHasher(time_cost=1, memory_cost_kib=64, parallelism=1)
    strong = PasswordHasher(time_cost=2, memory_cost_kib=128, parallelism=1)
    valid, rehashed = strong.verify("a long passphrase!", weak.hash("a long passphrase!"))
    assert valid
    assert rehashed is not None


def test_opaque_token_hash_is_stable_sha256() -> None:
    assert hash_opaque_token("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_principal_require() -> None:
    principal = Principal(
        user_id=uuid4(), org_id=uuid4(), email="a@example.com", roles=frozenset(), permissions=frozenset({"x:read"})
    )
    principal.require("x:read")
    with pytest.raises(PermissionDeniedError):
        principal.require("x:write")
