"""Pulling from Splunk: what is searched, what is sent on, what is refused, and what stays secret."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.ingest_pipeline.splunk import to_record
from app.ingest_pipeline.tests.test_splunk_mapping import OCSF_EVENT, SYSLOG_LINE, result
from app.ingest_pipeline.tests.test_wineventlog_text import PROCESS as RENDERED_4688
from app.ingest_pipeline.tests.test_winxml import SECURITY_4688, SYSMON_1
from app.splunk_collector import SplunkError, pull, search_events, splunk_client

TOKEN = "splunk-secret-token"  # a fake token for the stub server


def splunk_lines(*results: dict[str, Any]) -> str:
    lines = ['{"preview":true,"offset":0}', ""]  # a preview and a blank line: neither is a result
    lines += [json.dumps({"preview": False, "result": r}) for r in results]
    lines.append("{not json}")
    return "\n".join(lines)


def stub_splunk(body: str, status: int = 200) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, text=body)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://splunk.example:8089",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return client, seen


def stub_api(status: int = 200, body: dict[str, Any] | None = None) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        sent = json.loads(request.content)
        return httpx.Response(status, json=body or {"accepted": len(sent), "rejected": 0, "errors": []})

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://localhost:8080"), seen


def test_a_bare_search_is_prefixed_and_the_time_range_is_explicit() -> None:
    client, seen = stub_splunk(splunk_lines())
    list(search_events(client, search="index=windows sourcetype=XmlWinEventLog*", earliest="-2h", latest="now"))
    body = dict(pair.split("=", 1) for pair in seen[0].content.decode().split("&"))
    assert body["search"].startswith("search+index%3Dwindows")
    assert (body["earliest_time"], body["latest_time"], body["preview"]) == ("-2h", "now", "false")

    list(search_events(client, search="| tstats count", earliest="-2h", latest="now"))
    assert seen[1].content.decode().startswith("search=%7C+tstats"), "a command search is sent as written"


def test_previews_blank_lines_and_junk_are_skipped() -> None:
    client, _ = stub_splunk(splunk_lines(result("syslog", SYSLOG_LINE)))
    assert [r["sourcetype"] for r in search_events(client, search="x", earliest="-1h", latest="now")] == ["syslog"]


def test_the_result_limit_stops_the_stream() -> None:
    client, _ = stub_splunk(splunk_lines(*[result("syslog", SYSLOG_LINE)] * 10))
    assert len(list(search_events(client, search="x", earliest="-1h", latest="now", limit=3))) == 3


def test_pull_sends_only_the_records_this_source_parser_reads() -> None:
    splunk, _ = stub_splunk(
        splunk_lines(
            result("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", SYSMON_1),
            result("XmlWinEventLog:Security", SECURITY_4688),
            result("WinEventLog:Security", RENDERED_4688),
            result("cisco:asa", "%ASA-6-302013"),
            result("ocsf", json.dumps(OCSF_EVENT)),
        )
    )
    api, requests = stub_api()
    outcome = pull(
        splunk,
        api,
        search="index=windows",
        earliest="-24h",
        latest="now",
        ingest_token="ingest-token",  # a fake token for the stub API
        parser="windows_sysmon",
        out=lambda _: None,
    )

    assert (outcome.results, outcome.mapped, outcome.accepted) == (5, 1, 1)
    assert json.loads(requests[0].content) == [
        to_record(result("x", SYSMON_1) | {"sourcetype": "xmlwineventlog"}).record
    ]
    assert requests[0].headers["authorization"] == "Bearer ingest-token"
    assert outcome.unmapped == {
        # Both Security results — the XML one and the rendered-text one — need a windows_security source.
        "windows_security events need a source with that parser": 2,
        "cisco:asa: no parser is mapped to this sourcetype": 1,
        "ocsf events need a source with that parser": 1,
    }


def test_results_are_sent_in_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.splunk_collector.BATCH", 2)
    splunk, _ = stub_splunk(splunk_lines(*[result("syslog", SYSLOG_LINE)] * 5))
    api, requests = stub_api()
    outcome = pull(
        splunk,
        api,
        search="x",
        earliest="-1h",
        latest="now",
        ingest_token="t",  # a fake token for the stub API
        parser="linux_auth",
        out=lambda _: None,
    )
    assert [len(json.loads(r.content)) for r in requests] == [2, 2, 1]
    assert outcome.accepted == 5


def test_rejected_events_are_reported_with_their_reason() -> None:
    splunk, _ = stub_splunk(splunk_lines(result("syslog", SYSLOG_LINE)))
    api, _ = stub_api(body={"accepted": 0, "rejected": 1, "errors": [{"index": 0, "reason": "not an sshd line"}]})
    outcome = pull(
        splunk,
        api,
        search="x",
        earliest="-1h",
        latest="now",
        ingest_token="t",  # a fake token for the stub API
        parser="linux_auth",
        out=lambda _: None,
    )
    assert (outcome.accepted, outcome.rejected) == (0, 1)
    assert outcome.ingest_errors == ["not an sshd line"]


@pytest.mark.parametrize(("splunk_status", "api_status", "message"), [(401, 200, "token"), (200, 401, "ingest token")])
def test_authentication_failures_stop_the_pull_without_leaking_the_token(
    splunk_status: int, api_status: int, message: str
) -> None:
    splunk, _ = stub_splunk(splunk_lines(result("syslog", SYSLOG_LINE)), status=splunk_status)
    api, _ = stub_api(status=api_status)
    with pytest.raises(SplunkError, match=message) as raised:
        pull(
            splunk,
            api,
            search="x",
            earliest="-1h",
            latest="now",
            ingest_token="t",  # a fake token for the stub API
            parser="linux_auth",
            out=lambda _: None,
        )
    assert TOKEN not in str(raised.value)


def test_a_search_error_is_reported_with_splunks_message() -> None:
    splunk, _ = stub_splunk("Error in 'search' command: unbalanced quotes", status=400)
    with pytest.raises(SplunkError, match="unbalanced quotes"):
        list(search_events(splunk, search="x", earliest="-1h", latest="now"))


def test_the_client_sends_the_token_and_never_follows_redirects() -> None:
    client = splunk_client("https://splunk.example:8089/", TOKEN, verify=True, timeout=5.0)
    try:
        assert client.headers["authorization"] == f"Bearer {TOKEN}"
        assert client.follow_redirects is False
        assert str(client.base_url) == "https://splunk.example:8089"
    finally:
        client.close()
