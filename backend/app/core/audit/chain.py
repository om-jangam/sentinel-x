"""Hash-chain primitives for the tamper-evident audit log (docs/05 §4).

`entry_hash = SHA-256(prev_hash || canonical(entry))`, chained per org from a genesis hash.
Editing, deleting, inserting or reordering any entry breaks every hash after it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

GENESIS_HASH = "0" * 64


def normalize_json(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Round-trip through JSON so the hashed value equals what the database hands back."""
    if value is None:
        return None
    result: dict[str, Any] = json.loads(json.dumps(dict(value), default=str, allow_nan=False))
    return result


@dataclass(frozen=True, slots=True)
class ChainEntry:
    org_id: UUID
    chain_index: int
    ts: datetime
    actor_id: UUID | None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    context: dict[str, Any] | None
    correlation_id: str | None

    def canonical_bytes(self) -> bytes:
        document = {
            "org_id": str(self.org_id),
            "chain_index": self.chain_index,
            "ts": self.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "actor_id": None if self.actor_id is None else str(self.actor_id),
            "actor_type": self.actor_type,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "before": self.before,
            "after": self.after,
            "context": self.context,
            "correlation_id": self.correlation_id,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )


def compute_entry_hash(prev_hash: str, entry: ChainEntry) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + entry.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class ChainVerification:
    org_id: UUID
    valid: bool
    entries_checked: int
    head_hash: str | None
    broken_at_index: int | None = None
    reason: str | None = None


class ChainVerifier:
    """Streaming verifier: feed entries in `chain_index` order, then read `result()`."""

    def __init__(self, org_id: UUID) -> None:
        self._org_id = org_id
        self._expected_index = 0
        self._prev_hash = GENESIS_HASH
        self._checked = 0
        self._broken_at: int | None = None
        self._reason: str | None = None

    def feed(self, entry: ChainEntry, *, prev_hash: str, entry_hash: str) -> bool:
        """Returns False once the chain is known to be broken (stop feeding)."""
        if self._broken_at is not None:
            return False
        if entry.org_id != self._org_id:
            return self._fail(entry.chain_index, "entry belongs to a different org")
        if entry.chain_index != self._expected_index:
            return self._fail(
                entry.chain_index,
                f"expected chain_index {self._expected_index} (entry missing or inserted)",
            )
        if prev_hash != self._prev_hash:
            return self._fail(entry.chain_index, "prev_hash does not match preceding entry")
        if compute_entry_hash(prev_hash, entry) != entry_hash:
            return self._fail(entry.chain_index, "entry content does not match its hash")
        self._prev_hash = entry_hash
        self._expected_index += 1
        self._checked += 1
        return True

    def _fail(self, index: int, reason: str) -> bool:
        self._broken_at = index
        self._reason = reason
        return False

    def result(self) -> ChainVerification:
        return ChainVerification(
            org_id=self._org_id,
            valid=self._broken_at is None,
            entries_checked=self._checked,
            head_hash=None if self._checked == 0 else self._prev_hash,
            broken_at_index=self._broken_at,
            reason=self._reason,
        )
