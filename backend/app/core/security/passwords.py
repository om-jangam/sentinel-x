"""Argon2id password hashing via pwdlib (ADR-0010; passlib is unmaintained)."""

from __future__ import annotations

import secrets

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher


class PasswordHasher:
    def __init__(self, *, time_cost: int, memory_cost_kib: int, parallelism: int) -> None:
        self._hash = PasswordHash(
            (Argon2Hasher(time_cost=time_cost, memory_cost=memory_cost_kib, parallelism=parallelism),)
        )
        self._dummy_hash = self._hash.hash(secrets.token_urlsafe(24))

    def hash(self, password: str) -> str:
        return self._hash.hash(password)

    def verify(self, password: str, hashed: str) -> tuple[bool, str | None]:
        """Returns (valid, rehashed) — `rehashed` is set when work factors have been raised."""
        try:
            return self._hash.verify_and_update(password, hashed)
        except Exception:  # malformed/unknown hash format must never authenticate
            return False, None

    def burn(self, password: str) -> None:
        """Spend the same work as a real verification so unknown accounts can't be timed."""
        self._hash.verify(password, self._dummy_hash)
