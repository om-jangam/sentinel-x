from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.ingest_pipeline.ocsf import Category, EventClass, ObservableType, OcsfEvent, Severity, event_uid_for


def _auth(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "class_uid": 3002,
        "activity_id": 1,
        "severity_id": 2,
        "status_id": 2,
        "time": "2026-09-15T09:14:02.519Z",
        "metadata": {"version": "1.6.0", "product": {"name": "OpenSSH"}},
        "user": {"name": "root"},
        "src_endpoint": {"ip": "203.0.113.45", "port": 41822},
        "device": {"hostname": "web-01"},
    }
    event.update(overrides)
    return event


def test_derives_category_type_uid_and_observables() -> None:
    event = OcsfEvent.model_validate(_auth())
    assert event.category_uid is Category.IAM
    assert event.type_uid == 300201
    assert event.activity_name == "Logon"
    assert event.data_stream == "events-ocsf-iam"
    assert {(o.name, o.type_id, o.value) for o in event.observables} == {
        ("src_endpoint.ip", ObservableType.IP_ADDRESS, "203.0.113.45"),
        ("device.hostname", ObservableType.HOSTNAME, "web-01"),
        ("user.name", ObservableType.USER_NAME, "root"),
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1_789_464_842_519, datetime(2026, 9, 15, 9, 34, 2, 519000, tzinfo=UTC)),
        (1_789_464_842, datetime(2026, 9, 15, 9, 34, 2, tzinfo=UTC)),
        ("1789464842519", datetime(2026, 9, 15, 9, 34, 2, 519000, tzinfo=UTC)),
        ("2026-09-15T11:34:02.519+02:00", datetime(2026, 9, 15, 9, 34, 2, 519000, tzinfo=UTC)),
    ],
)
def test_time_accepts_epoch_ms_seconds_and_rfc3339(value: object, expected: datetime) -> None:
    assert OcsfEvent.model_validate(_auth(time=value)).time == expected


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"category_uid": 4}, "does not match class_uid"),
        ({"activity_id": 42}, "not defined for Authentication"),
        ({"type_uid": 300202}, "type_uid must be 300201"),
        ({"user": None}, "require user"),
        ({"class_uid": 9999}, "class_uid"),
        ({"time": "yesterday"}, "RFC 3339"),
        ({"time": True}, "RFC 3339"),
        ({"metadata": {"version": "2.0.0", "product": {"name": "x"}}}, "OCSF 1.x"),
        ({"src_endpoint": {"ip": "999.1.1.1"}}, "ip"),
        ({"src_endpoint": {"port": 70000}}, "port"),
        ({"unmapped": {"blob": "x" * 20_000}}, "unmapped exceeds"),
        ({"severity_id": 7}, "severity_id"),
    ],
)
def test_invalid_events_are_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OcsfEvent.model_validate(_auth(**overrides))


def test_future_events_beyond_clock_skew_are_rejected() -> None:
    with pytest.raises(ValidationError, match="future"):
        OcsfEvent.model_validate(_auth(time=(datetime.now(UTC) + timedelta(days=2)).isoformat()))


def test_other_and_unknown_activities_are_allowed() -> None:
    assert OcsfEvent.model_validate(_auth(activity_id=99)).activity_name == "Other"
    assert OcsfEvent.model_validate(_auth(activity_id=0)).activity_name == "Unknown"


def test_network_activity_needs_an_endpoint() -> None:
    base = {
        "class_uid": 4001,
        "activity_id": 6,
        "severity_id": 1,
        "time": "2026-09-15T09:43:41Z",
        "metadata": {"product": {"name": "Zeek"}},
    }
    with pytest.raises(ValidationError, match="src_endpoint or dst_endpoint"):
        OcsfEvent.model_validate(base)
    assert OcsfEvent.model_validate({**base, "dst_endpoint": {"ip": "192.0.2.66"}}).category_uid is Category.NETWORK


def test_unknown_attributes_are_ignored_not_rejected() -> None:
    event = OcsfEvent.model_validate(_auth(enrichments=[{"name": "geo"}], user={"name": "root", "email_addr": "x"}))
    assert "enrichments" not in event.model_dump()


def test_explicit_observables_are_kept() -> None:
    event = OcsfEvent.model_validate(_auth(observables=[{"name": "custom", "type_id": 99, "value": "v"}]))
    assert [o.name for o in event.observables] == ["custom"]


def test_fingerprint_is_content_addressed_per_org_and_source() -> None:
    first = OcsfEvent.model_validate(_auth())
    same = OcsfEvent.model_validate(_auth(user={"name": "root"}, severity_id=2))
    other = OcsfEvent.model_validate(_auth(user={"name": "admin"}))
    assert first.fingerprint(org_id="o", source_id="s") == same.fingerprint(org_id="o", source_id="s")
    assert first.fingerprint(org_id="o", source_id="s") != other.fingerprint(org_id="o", source_id="s")
    assert first.fingerprint(org_id="o", source_id="s") != first.fingerprint(org_id="o", source_id="s2")


def test_document_shape() -> None:
    event = OcsfEvent.model_validate(_auth())
    ingested = datetime(2026, 9, 15, 9, 15, tzinfo=UTC)
    document = event.to_document(org_id="org-1", source_id="src-1", event_uid="evt-1", ingested_at=ingested)

    assert document["time"] == 1_789_463_642_519
    assert document["@timestamp"] == "2026-09-15T09:14:02.519000Z"
    assert document["class_name"] == EventClass.AUTHENTICATION.caption == "Authentication"
    assert document["category_name"] == "Identity & Access Management"
    assert document["activity_name"] == "Logon"
    assert document["severity"] == Severity.LOW.name.title()
    assert document["status"] == "Failure"
    assert document["src_endpoint"] == {"ip": "203.0.113.45", "port": 41822}
    assert document["sx"] == {
        "org_id": "org-1",
        "source_id": "src-1",
        "event_uid": "evt-1",
        "ingested_at": "2026-09-15T09:15:00.000000Z",
        "fingerprint": event.fingerprint(org_id="org-1", source_id="src-1"),
    }
    assert "status_id" in document
    assert all(value is not None for value in document.values())


def test_class_captions() -> None:
    assert EventClass.DNS_ACTIVITY.caption == "DNS Activity"
    assert EventClass.HTTP_ACTIVITY.caption == "HTTP Activity"


def test_event_uid_is_deterministic_per_fingerprint() -> None:
    first = event_uid_for("a" * 64)
    assert first == event_uid_for("a" * 64), "every delivery of a record must cite the same id"
    assert first != event_uid_for("b" * 64)
    assert UUID(first).version == 5


def _process(**file: Any) -> dict[str, Any]:
    return {
        "class_uid": 1007,
        "activity_id": 1,
        "severity_id": 1,
        "time": "2026-09-15T09:42:37Z",
        "metadata": {"product": {"name": "EDR"}},
        "process": {"name": "evil.exe", "file": {"path": r"C:\evil.exe", **file}},
    }


def test_file_hashes_are_validated_normalised_and_observable() -> None:
    sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    event = OcsfEvent.model_validate(_process(hashes=[{"algorithm_id": 3, "value": sha256}]))

    assert event.process is not None
    assert event.process.file is not None
    assert event.process.file.hashes is not None
    assert event.process.file.hashes[0].value == sha256.lower()
    assert ("process.file.hashes.value", ObservableType.HASH, sha256.lower()) in {
        (o.name, o.type_id, o.value) for o in event.observables
    }


@pytest.mark.parametrize(
    ("fingerprint", "message"),
    [
        ({"algorithm_id": 3, "value": "abc"}, "SHA256 hash must be 64 hex"),
        ({"algorithm_id": 1, "value": "z" * 32}, "MD5 hash must be 32 hex"),
        ({"algorithm_id": 42, "value": "x"}, "algorithm_id"),
    ],
)
def test_malformed_hashes_are_rejected(fingerprint: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OcsfEvent.model_validate(_process(hashes=[fingerprint]))


def test_non_cryptographic_hashes_are_kept_as_given() -> None:
    event = OcsfEvent.model_validate(_process(hashes=[{"algorithm_id": 6, "value": "T1A2b3"}]))
    assert event.process is not None
    assert event.process.file is not None
    assert event.process.file.hashes
    assert event.process.file.hashes[0].value == "T1A2b3"
