"""Sysmon → OCSF: every supported event ID maps to the right class, activity and attributes."""

from __future__ import annotations

from typing import Any

import pytest

from app.ingest_pipeline.ocsf import Category, EventClass, HashAlgorithm, OcsfEvent, Status
from app.ingest_pipeline.parsers import ParseError, normalize
from app.ingest_pipeline.tests import sysmon_records as r


def parse(record: dict[str, Any]) -> OcsfEvent:
    return normalize("windows_sysmon", record)


@pytest.mark.parametrize(
    ("record", "class_uid", "activity_id"),
    [
        (r.PROCESS_CREATE, EventClass.PROCESS_ACTIVITY, 1),
        (r.NETWORK, EventClass.NETWORK_ACTIVITY, 1),
        (r.TERMINATE, EventClass.PROCESS_ACTIVITY, 2),
        (r.IMAGE_LOAD, EventClass.MODULE_ACTIVITY, 1),
        (r.REMOTE_THREAD, EventClass.PROCESS_ACTIVITY, 4),
        (r.LSASS_ACCESS, EventClass.PROCESS_ACTIVITY, 3),
        (r.FILE_CREATE, EventClass.FILE_SYSTEM_ACTIVITY, 1),
        (r.REG_CREATE_KEY, EventClass.REGISTRY_KEY_ACTIVITY, 1),
        (r.REG_SET_RUN_KEY, EventClass.REGISTRY_VALUE_ACTIVITY, 2),
        (r.REG_RENAME, EventClass.REGISTRY_KEY_ACTIVITY, 5),
        (r.DNS, EventClass.DNS_ACTIVITY, 1),
        (r.FILE_DELETE, EventClass.FILE_SYSTEM_ACTIVITY, 4),
    ],
)
def test_each_event_id_maps_to_its_ocsf_class(record: dict[str, Any], class_uid: EventClass, activity_id: int) -> None:
    event = parse(record)
    assert (event.class_uid, event.activity_id) == (class_uid, activity_id)
    assert event.type_uid == int(class_uid) * 100 + activity_id
    assert event.metadata.product.name == "Sysmon"
    assert event.metadata.log_name == "Microsoft-Windows-Sysmon/Operational"
    assert event.device is not None
    assert event.device.hostname == r.HOST
    assert event.unmapped is not None
    assert event.unmapped["event_id"] == record["EventID"]


def test_registry_classes_belong_to_system_activity() -> None:
    """OCSF Windows extension classes are numbered 201001/201002 but sit in category 1."""
    assert EventClass.REGISTRY_KEY_ACTIVITY.category is Category.SYSTEM
    assert EventClass.REGISTRY_VALUE_ACTIVITY.category is Category.SYSTEM
    event = parse(r.REG_SET_RUN_KEY)
    assert event.category_uid is Category.SYSTEM
    assert event.data_stream == "events-ocsf-system"


def test_process_creation_keeps_process_parent_and_file_details() -> None:
    event = parse(r.PROCESS_CREATE)
    process = event.process
    assert process is not None
    assert process.file is not None
    assert process.name == "powershell.exe"
    assert process.pid == 6732
    assert process.uid == r.PS_GUID
    assert process.cmd_line is not None
    assert "-EncodedCommand" in process.cmd_line
    assert process.user is not None
    assert (process.user.domain, process.user.name) == ("CORP", "jsmith")
    assert process.integrity == "Medium"
    assert process.working_directory == "C:\\Users\\jsmith\\Documents\\"
    assert process.file.company_name == "Microsoft Corporation"
    assert process.file.desc == "Windows PowerShell"
    assert process.file.product is not None
    assert (process.file.product.name or "").startswith("Microsoft")
    parent = process.parent_process
    assert parent is not None
    assert parent.name == "WINWORD.EXE"
    assert parent.pid == 5120
    assert parent.cmd_line is not None
    assert "invoice.docm" in parent.cmd_line
    # The parent is not repeated as the actor process (a Sysmon rule on Image must not match the parent).
    assert event.actor is not None
    assert event.actor.process is None
    assert event.actor.user is not None
    assert event.actor.user.name == "jsmith"
    assert event.unmapped is not None
    assert event.unmapped["original_file_name"] == "PowerShell.EXE"
    assert event.unmapped["user"] == "CORP\\jsmith"


def test_hashes_are_parsed_validated_and_kept_as_written() -> None:
    event = parse(r.PROCESS_CREATE)
    assert event.process is not None
    assert event.process.file is not None
    hashes = {h.algorithm: (h.algorithm_id, h.value) for h in event.process.file.hashes or []}
    assert hashes["MD5"] == (HashAlgorithm.MD5, r.MD5)
    assert hashes["SHA256"] == (HashAlgorithm.SHA256, r.SHA256), "lower-cased by validation"
    assert hashes["IMPHASH"][0] is HashAlgorithm.OTHER
    assert event.unmapped is not None
    assert "IMPHASH=F1D2" in event.unmapped["hashes"]
    assert {o.value for o in event.observables if o.name == "process.file.hashes.value"} >= {r.MD5, r.SHA256}


def test_malformed_hash_entries_are_skipped_not_guessed() -> None:
    record = {**r.PROCESS_CREATE, "EventData": {**r.PROCESS_CREATE["EventData"], "Hashes": "MD5=nothex,SHA256=,X=1"}}
    event = parse(record)
    assert event.process is not None
    assert event.process.file is not None
    assert event.process.file.hashes is None


def test_network_connection_names_the_process_and_direction() -> None:
    event = parse(r.NETWORK)
    assert event.src_endpoint is not None
    assert str(event.src_endpoint.ip) == "10.20.30.47"
    assert event.dst_endpoint is not None
    assert str(event.dst_endpoint.ip) == "192.0.2.66"
    assert event.dst_endpoint.port == 443
    assert event.dst_endpoint.hostname is None
    assert event.connection_info is not None
    assert (event.connection_info.protocol_name, event.connection_info.direction_id) == ("tcp", 2)
    assert event.actor is not None
    assert event.actor.process is not None
    assert event.actor.process.name == "powershell.exe"
    assert event.unmapped is not None
    assert event.unmapped["initiated"] == "true"


def test_inbound_connection_direction() -> None:
    record = {**r.NETWORK, "EventData": {**r.NETWORK["EventData"], "Initiated": "false"}}
    event = parse(record)
    assert event.connection_info is not None
    assert event.connection_info.direction_id == 1


def test_process_access_records_source_target_and_access_mask() -> None:
    event = parse(r.LSASS_ACCESS)
    assert event.actor is not None
    assert event.actor.process is not None
    assert event.actor.process.file is not None
    assert event.actor.process.file.path == r.MIMIKATZ
    assert event.actor.process.uid is not None, "Sysmon 10 spells it SourceProcessGUID"
    assert event.process is not None
    assert event.process.name == "lsass.exe"
    assert event.process.user is not None
    assert event.process.user.name == "SYSTEM"
    assert event.actual_permissions == 0x1010
    assert event.unmapped is not None
    assert event.unmapped["granted_access"] == "0x1010"
    assert "ntdll.dll" in event.unmapped["call_trace"]


def test_remote_thread_is_an_injection() -> None:
    event = parse(r.REMOTE_THREAD)
    assert event.injection_type == "Remote Thread"
    assert event.process is not None
    assert event.process.name == "explorer.exe"
    assert event.module is not None
    assert event.module.start_address == "0x00000245A1B20000"


def test_image_load_records_the_module_and_loader() -> None:
    event = parse(r.IMAGE_LOAD)
    assert event.module is not None
    assert event.module.file is not None
    assert event.module.file.name == "vaultcli.dll"
    assert event.module.file.company_name == "Microsoft Corporation"
    assert event.actor is not None
    assert event.actor.process is not None
    assert event.actor.process.name == "powershell.exe"
    assert event.unmapped is not None
    assert event.unmapped["signed"] == "true"
    assert any(o.name == "module.file.path" for o in event.observables)


def test_registry_value_set_keeps_path_name_and_data() -> None:
    event = parse(r.REG_SET_RUN_KEY)
    assert event.reg_value is not None
    assert event.reg_value.path.endswith(r"\CurrentVersion\Run\Updater")
    assert event.reg_value.name == "Updater"
    assert event.reg_value.data == r.MIMIKATZ
    assert event.unmapped is not None
    assert event.unmapped["event_type"] == "SetValue"


def test_registry_rename_keeps_old_and_new_paths() -> None:
    event = parse(r.REG_RENAME)
    assert event.reg_key is not None
    assert event.reg_key.path == r"HKLM\SOFTWARE\Example\New"
    assert event.prev_reg_key is not None
    assert event.prev_reg_key.path == r"HKLM\SOFTWARE\Example\Old"


@pytest.mark.parametrize(
    ("event_type", "class_uid", "activity_id"),
    [
        ("DeleteKey", EventClass.REGISTRY_KEY_ACTIVITY, 4),
        ("DeleteValue", EventClass.REGISTRY_VALUE_ACTIVITY, 4),
    ],
)
def test_registry_deletes(event_type: str, class_uid: EventClass, activity_id: int) -> None:
    record = {**r.REG_CREATE_KEY, "EventData": {**r.REG_CREATE_KEY["EventData"], "EventType": event_type}}
    event = parse(record)
    assert (event.class_uid, event.activity_id) == (class_uid, activity_id)


def test_dns_query_keeps_addresses_and_skips_cname_records() -> None:
    event = parse(r.DNS)
    assert event.query is not None
    assert event.query.hostname == "update.bad.example"
    assert [a.rdata for a in event.answers or []] == ["192.0.2.66"]
    assert event.status_id is Status.SUCCESS
    failed = {**r.DNS, "EventData": {**r.DNS["EventData"], "QueryStatus": "9003", "QueryResults": "-"}}
    assert parse(failed).status_id is Status.FAILURE


def test_utc_time_is_used_when_the_forwarder_sends_no_time_created() -> None:
    record = {k: v for k, v in r.PROCESS_CREATE.items() if k != "TimeCreated"}
    event = parse(record)
    assert event.time.isoformat().startswith("2026-09-15T10:13:54.120")


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"EventID": 255, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": {}}, "unsupported Sysmon event 255"),
        ({"TimeCreated": "2026-09-15T10:00:00Z"}, "no numeric EventID"),
        ({"EventID": 1, "EventData": {"Image": "C:\\x.exe"}}, "no TimeCreated or UtcTime"),
        ({"EventID": 1, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": {}}, "has no Image"),
        ({"EventID": 3, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": {"Image": "x"}}, "no source"),
        (
            {"EventID": 13, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": {"EventType": "SetValue"}},
            "TargetObject",
        ),
        (
            {
                "EventID": 13,
                "TimeCreated": "2026-09-15T10:00:00Z",
                "EventData": {"EventType": "X", "TargetObject": "k"},
            },
            "unsupported Sysmon registry EventType",
        ),
        ({"EventID": 1, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": "x"}, "EventData must be an object"),
    ],
)
def test_unmappable_records_are_rejected_with_a_reason(record: dict[str, Any], message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(record)
