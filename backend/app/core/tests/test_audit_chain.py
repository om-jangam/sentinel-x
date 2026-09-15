from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import update

from app.core.audit.chain import GENESIS_HASH, ChainEntry, ChainVerifier, compute_entry_hash
from app.core.audit.models import AuditLogModel
from app.core.audit.port import AuditEvent
from app.core.audit.repository import list_audit_entries, list_audited_org_ids, verify_audit_chain
from app.core.audit.writer import SqlAuditRecorder
from app.core.container import Container


def _entry(org_id: UUID, index: int, action: str = "x.y") -> ChainEntry:
    return ChainEntry(
        org_id=org_id,
        chain_index=index,
        ts=datetime(2026, 9, 15, 12, 0, index, 123456, tzinfo=UTC),
        actor_id=None,
        actor_type="system",
        action=action,
        resource_type="thing",
        resource_id=str(index),
        before=None,
        after={"k": index, "nested": {"b": 1, "a": [1, 2]}},
        context=None,
        correlation_id=None,
    )


def _chain(org_id: UUID, n: int) -> list[tuple[ChainEntry, str, str]]:
    prev = GENESIS_HASH
    rows = []
    for i in range(n):
        entry = _entry(org_id, i)
        entry_hash = compute_entry_hash(prev, entry)
        rows.append((entry, prev, entry_hash))
        prev = entry_hash
    return rows


def _verify(org_id: UUID, rows: list[tuple[ChainEntry, str, str]]) -> ChainVerifier:
    verifier = ChainVerifier(org_id)
    for entry, prev, entry_hash in rows:
        if not verifier.feed(entry, prev_hash=prev, entry_hash=entry_hash):
            break
    return verifier


def test_canonical_form_is_key_order_independent() -> None:
    org = uuid4()
    a = _entry(org, 0)
    reordered = dataclasses.replace(a, after={"nested": {"a": [1, 2], "b": 1}, "k": 0})
    assert a.canonical_bytes() == reordered.canonical_bytes()
    assert compute_entry_hash(GENESIS_HASH, a) == compute_entry_hash(GENESIS_HASH, reordered)


def test_valid_chain_verifies() -> None:
    org = uuid4()
    result = _verify(org, _chain(org, 5)).result()
    assert result.valid
    assert result.entries_checked == 5
    assert result.head_hash == _chain(org, 5)[-1][2]


def test_empty_chain_is_valid() -> None:
    result = ChainVerifier(uuid4()).result()
    assert result.valid
    assert result.entries_checked == 0
    assert result.head_hash is None


def test_tampered_content_is_detected() -> None:
    org = uuid4()
    rows = _chain(org, 4)
    _, prev, entry_hash = rows[2]
    rows[2] = (_entry(org, 2, action="tampered"), prev, entry_hash)
    result = _verify(org, rows).result()
    assert not result.valid
    assert result.broken_at_index == 2
    assert "hash" in (result.reason or "")


def test_deleted_entry_is_detected() -> None:
    org = uuid4()
    rows = _chain(org, 4)
    del rows[1]
    result = _verify(org, rows).result()
    assert not result.valid
    assert result.broken_at_index == 2


def test_rehashed_forgery_still_breaks_the_link() -> None:
    """An attacker who recomputes one entry's hash must also rewrite every later entry."""
    org = uuid4()
    rows = _chain(org, 3)
    forged = _entry(org, 1, action="forged")
    rows[1] = (forged, rows[1][1], compute_entry_hash(rows[1][1], forged))
    result = _verify(org, rows).result()
    assert not result.valid
    assert result.broken_at_index == 2
    assert "prev_hash" in (result.reason or "")


async def test_writer_builds_a_verifiable_per_org_chain(container: Container) -> None:
    org_a, org_b = uuid4(), uuid4()
    async with container.database.sessionmaker() as session:
        recorder = SqlAuditRecorder(session)
        for i in range(3):
            await recorder.record(
                AuditEvent(
                    org_id=org_a,
                    action="thing.changed",
                    resource_type="thing",
                    resource_id=str(i),
                    after={"i": i, "id": uuid4()},
                )
            )
        await recorder.record(AuditEvent(org_id=org_b, action="thing.changed", resource_type="thing"))
        await session.commit()

    async with container.database.sessionmaker() as session:
        result_a = await verify_audit_chain(session, org_a)
        result_b = await verify_audit_chain(session, org_b)
        assert (result_a.valid, result_a.entries_checked) == (True, 3)
        assert (result_b.valid, result_b.entries_checked) == (True, 1)
        assert set(await list_audited_org_ids(session)) == {org_a, org_b}
        newest = await list_audit_entries(session, org_a, limit=2)
        assert [e.chain_index for e in newest] == [2, 1]
        older = await list_audit_entries(session, org_a, limit=2, before_index=1)
        assert [e.chain_index for e in older] == [0]


async def test_database_tampering_is_detected(container: Container) -> None:
    org = uuid4()
    async with container.database.sessionmaker() as session:
        recorder = SqlAuditRecorder(session)
        for i in range(3):
            await recorder.record(AuditEvent(org_id=org, action="role.updated", resource_type="role", after={"i": i}))
        await session.commit()

    if container.database.dialect_name == "postgresql":
        return  # the append-only trigger blocks the UPDATE itself; covered by the migration test

    async with container.database.sessionmaker() as session:
        await session.execute(
            update(AuditLogModel)
            .where(AuditLogModel.org_id == org, AuditLogModel.chain_index == 1)
            .values(after={"i": 999})
        )
        await session.commit()

    async with container.database.sessionmaker() as session:
        result = await verify_audit_chain(session, org)
    assert not result.valid
    assert result.broken_at_index == 1
