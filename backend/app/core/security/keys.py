"""RS256 signing keys, key rotation and JWKS (ADR-0010, docs/07 §2).

Verifiers only ever need public keys. During rotation the previous public key stays in the
verification set so tokens issued before the switch remain valid until they expire.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings

logger = logging.getLogger(__name__)

PRODUCTION_KEY_SIZE = 3072


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_private_key(key_size: int = PRODUCTION_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def private_key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("JWT signing key must be an RSA private key")
    if key.key_size < 2048:
        raise ValueError("JWT signing key must be at least 2048 bits")
    return key


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("JWT verification key must be an RSA public key")
    return key


def jwk_thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """RFC 7638 thumbprint — a stable, content-derived `kid`."""
    numbers = public_key.public_numbers()
    members = {"e": _b64url_uint(numbers.e), "kty": "RSA", "n": _b64url_uint(numbers.n)}
    digest = hashlib.sha256(json.dumps(members, separators=(",", ":"), sort_keys=True).encode())
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")


def public_jwk(public_key: rsa.RSAPublicKey, kid: str) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


@dataclass(frozen=True, slots=True)
class KeyRing:
    signing_key: rsa.RSAPrivateKey
    signing_kid: str
    verification_keys: Mapping[str, rsa.RSAPublicKey]

    @classmethod
    def build(
        cls,
        signing_key: rsa.RSAPrivateKey,
        previous_public_keys: Sequence[rsa.RSAPublicKey] = (),
    ) -> KeyRing:
        public = signing_key.public_key()
        kid = jwk_thumbprint(public)
        verification = {jwk_thumbprint(k): k for k in previous_public_keys}
        verification[kid] = public
        return cls(signing_key=signing_key, signing_kid=kid, verification_keys=verification)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [public_jwk(key, kid) for kid, key in self.verification_keys.items()]}


@lru_cache(maxsize=1)
def _ephemeral_development_key() -> rsa.RSAPrivateKey:
    return generate_private_key(key_size=2048)


def load_keyring(settings: Settings) -> KeyRing:
    if settings.jwt_private_key is not None:
        signing = load_private_key(settings.jwt_private_key.get_secret_value().encode())
    elif settings.jwt_private_key_file is not None:
        signing = load_private_key(Path(settings.jwt_private_key_file).read_bytes())
    elif settings.is_production:  # also enforced by Settings validation
        raise RuntimeError("a JWT signing key is required in production")
    else:
        logger.warning(
            "No JWT signing key configured; using an ephemeral development key. "
            "Tokens will not survive a restart. Run `sentinelx generate-keys`."
        )
        signing = _ephemeral_development_key()

    previous: list[rsa.RSAPublicKey] = []
    if settings.jwt_previous_public_key_file is not None:
        previous.append(load_public_key(Path(settings.jwt_previous_public_key_file).read_bytes()))
    return KeyRing.build(signing, previous)
