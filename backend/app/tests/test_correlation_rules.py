"""The correlation rules' boundaries, using crafted SSH log lines through the real parser, detection and SQL."""

from __future__ import annotations

from datetime import UTC, datetime

from app.conftest import Seeded
from app.core.container import Container
from app.modules.correlation.domain.incidents import CorrelationRule, IncidentStatus, LinkKind, Resolution
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.detection.tests.conftest import document
from app.tests.test_correlation_pipeline import _incidents, _run

ATTACKER, OTHER = "203.0.113.45", "198.51.100.99"


def invalid_user(at: str, *, host: str = "web-01", ip: str = ATTACKER, user: str = "admin") -> dict[str, object]:
    line = f"2026-09-15T{at}+00:00 {host} sshd[2211]: Invalid user {user} from {ip} port 41822"
    return document({"message": line}, "linux_auth")


def accepted(at: str, *, host: str = "web-01", ip: str = ATTACKER, user: str = "deploy") -> dict[str, object]:
    line = f"2026-09-15T{at}+00:00 {host} sshd[2231]: Accepted password for {user} from {ip} port 41958 ssh2"
    return document({"message": line}, "linux_auth")


async def test_findings_far_apart_open_separate_incidents(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, [[invalid_user("09:00:00")], [invalid_user("12:30:00")]])
    assert len(await _incidents(container, seeded)) == 2  # 3.5h apart: beyond the 2h correlation window


async def test_findings_within_the_window_join(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, [[invalid_user("09:00:00")], [invalid_user("10:45:00", user="oracle")]])
    [incident] = await _incidents(container, seeded)
    assert incident.incident.finding_count == 2
    joined = next(link for link in incident.links if link.rule is CorrelationRule.SHARED_ENTITY)
    assert {m.key for m in joined.matched} == {"host:web-01", f"ip:{ATTACKER}"}


async def test_same_user_name_on_different_hosts_does_not_join(container: Container, seeded: Seeded) -> None:
    await _run(
        container,
        seeded,
        [[invalid_user("09:00:00", host="web-01", ip=ATTACKER)], [invalid_user("09:01:00", host="db-02", ip=OTHER)]],
    )
    details = await _incidents(container, seeded)
    assert len(details) == 2  # admin@web-01 and admin@db-02 are different accounts
    assert {e.key for d in details for e in d.entities if e.type == "user"} == {"user:admin@web-01", "user:admin@db-02"}


async def test_a_closed_incident_is_not_reopened_by_new_findings(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, [[invalid_user("09:00:00")]])
    [first] = await _incidents(container, seeded)
    async with container.database.sessionmaker() as session:
        uow = SqlCorrelationUnitOfWork(session)
        first.incident.change_status(
            IncidentStatus.CLOSED, Resolution.FALSE_POSITIVE, expected_version=1, now=datetime.now(UTC)
        )
        await uow.incidents.update(first.incident)
        await uow.commit()

    await _run(container, seeded, [[invalid_user("09:10:00", user="oracle")]])
    details = await _incidents(container, seeded)
    assert len(details) == 2
    assert {d.incident.status for d in details} == {IncidentStatus.CLOSED, IncidentStatus.NEW}


async def test_logon_completes_failures_from_the_same_source_only(container: Container, seeded: Seeded) -> None:
    await _run(
        container,
        seeded,
        [
            [invalid_user("09:00:00")],
            [accepted("09:05:00", ip=OTHER)],  # a different source: unrelated
            [accepted("10:30:00")],  # the same source, but 90 minutes later: outside the sequence window
            [accepted("09:20:00", host="db-02")],  # the same source against another host
            [accepted("09:10:00")],  # the same source, same host, 10 minutes later: completes the story
        ],
    )
    [incident] = await _incidents(container, seeded)
    events = [link for link in incident.links if link.kind is LinkKind.EVENT]
    assert [link.first_seen.strftime("%H:%M") for link in events] == ["09:10"]
    assert incident.incident.severity == "High"


async def test_a_logon_before_any_failure_is_not_linked(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, [[accepted("08:55:00")], [invalid_user("09:00:00")]])
    [incident] = await _incidents(container, seeded)
    assert all(link.kind is LinkKind.FINDING for link in incident.links)


async def test_logons_without_findings_create_nothing(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, [[accepted("09:00:00"), accepted("09:01:00", ip=OTHER)]])
    assert await _incidents(container, seeded) == []
