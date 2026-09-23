"""End-to-end demo against a running deployment, over HTTP only (roadmap Phase 7).

    sentinelx demo --api-url http://localhost:8080 --email admin@example.com [--analyse]

Walks the investigation workflow the way an analyst's tools would:
1. registers three sources and sends the sample attack stories, shifted to "now";
2. waits for the pipeline (indexer, detection, correlation, enrichment) to process them;
3. reports the findings and the incidents they became;
4. for each incident, reports the timeline, entity graph, threat intel, and one stored event read back from
   the event store (the last hop from a timeline step to raw evidence);
5. with --analyse, asks the AI assistant and prints what survived validation.

It exits non-zero if a stage does not produce what the samples should: 15 findings and 2 incidents.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from app.core.clock import utcnow

EXPECTED_FINDINGS = 15  # 12 from the platform rules, 3 from the SigmaHQ pack on the same encoded command
EXPECTED_INCIDENTS = 2


class DemoError(RuntimeError):
    pass


def _wait(what: str, check: Callable[[], Any], *, timeout: float, interval: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() > deadline:
            raise DemoError(f"timed out waiting for {what}")
        time.sleep(interval)


def run_demo(
    api_url: str,
    email: str,
    password: str,
    samples: Path,
    *,
    analyse: bool = False,
    wait_seconds: float = 180.0,
    out: Callable[[str], None] = print,
) -> int:
    from app.cli import SAMPLE_SOURCES, _read_sample, _sample_time, _shift

    client = httpx.Client(base_url=api_url.rstrip("/"), timeout=httpx.Timeout(30.0, read=700.0))
    try:
        login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        if login.status_code != 200:
            raise DemoError(f"login failed ({login.status_code}): {login.text[:200]}")
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        started = utcnow()

        datasets = [(parser, _read_sample(samples / filename)) for _, parser, filename, _ in SAMPLE_SOURCES]
        times = [t for _, records in datasets for t in map(_sample_time, records) if t is not None]
        delta = started - timedelta(minutes=5) - max(times)
        stamp = str(int(time.time()))
        out("1. sending the sample attack stories")
        for parser, records in datasets:
            created = client.post(
                "/api/v1/ingest/sources",
                headers=headers,
                json={"name": f"demo-{parser.replace('_', '-')}-{stamp}", "parser": parser},
            )
            if created.status_code != 201:
                raise DemoError(f"could not register a {parser} source: {created.text[:200]}")
            sent = client.post(
                "/api/v1/ingest/events",
                headers={"Authorization": f"Bearer {created.json()['token']}"},
                json=[_shift(r, delta) for r in records],
            )
            body = sent.json()
            out(f"   {parser:<17} accepted {body.get('accepted')}, rejected {body.get('rejected')}")

        since = (started - timedelta(minutes=1)).isoformat()

        def new_findings() -> list[dict[str, Any]]:
            response = client.get("/api/v1/findings", headers=headers, params={"limit": 200})
            items: list[dict[str, Any]] = response.json().get("items", [])
            fresh = [f for f in items if f["created_at"] >= since]
            return fresh if len(fresh) >= EXPECTED_FINDINGS else []

        out("2. waiting for detection")
        findings = _wait("findings", new_findings, timeout=wait_seconds)
        out(f"   {len(findings)} findings")

        def new_incidents() -> list[dict[str, Any]]:
            items: list[dict[str, Any]] = client.get(
                "/api/v1/incidents", headers=headers, params={"limit": 200}
            ).json()["items"]
            # Updated, not only created: on a second run the same story joins the incidents the first one opened.
            fresh = [i for i in items if i["updated_at"] >= since]
            return fresh if len(fresh) >= EXPECTED_INCIDENTS else []

        out("3. waiting for correlation")
        incidents = _wait("incidents", new_incidents, timeout=wait_seconds)
        for incident in incidents:
            out(f"   [{incident['severity']}] {incident['title']}")
            out(f"       {incident['finding_count']} findings, {incident['event_count']} events")

        out("4. reconstructing each incident")
        for incident in incidents:
            base = f"/api/v1/incidents/{incident['id']}"
            timeline = client.get(f"{base}/timeline", headers=headers).json()
            graph = client.get(f"{base}/graph", headers=headers).json()
            detail = client.get(base, headers=headers).json()
            keys = [entity["key"] for entity in detail["entities"]]
            intel = client.post("/api/v1/intel/lookup", headers=headers, json={"indicators": keys}).json()
            flagged = [r for r in intel.get("results", []) if r["status"] == "found"]
            out(f"   {incident['title'][:70]}")
            out(
                f"       timeline {len(timeline['steps'])} steps, graph {len(graph['nodes'])} nodes / "
                f"{len(graph['edges'])} edges, unresolved evidence {len(timeline['unresolved_events'])}"
            )
            said = ", ".join(f"{r['indicator']} {r['verdict']} ({r['provider']})" for r in flagged)
            out(f"       threat intel: {said or 'none'}")
            first = timeline["steps"][0]["events"][0] if timeline["steps"] else None
            if first:
                stored = client.get(f"/api/v1/events/{first}", headers=headers)
                reached = (
                    "read back from the event store" if stored.status_code == 200 else f"HTTP {stored.status_code}"
                )
                out(f"       first timeline event {first[:8]}…: {reached}")

        if analyse:
            out("5. asking the AI assistant (a local model can take minutes)")
            status = client.get("/api/v1/assistant", headers=headers).json()
            if not status.get("enabled"):
                out("   the assistant is not configured; skipped")
            else:
                top = max(incidents, key=lambda i: i["severity_id"])
                record = client.post(f"/api/v1/incidents/{top['id']}/analyses", headers=headers).json()
                seconds = record.get("duration_ms", 0) / 1000
                out(f"   {status['provider']}/{status['model']}: {record.get('status')} in {seconds:.0f}s")
                for statement in (record.get("output") or {}).get("statements", []):
                    cited = len(statement.get("evidence", []))
                    out(f"     {statement['kind']:<11} {statement['text'][:100]}  [{cited} cited]")
                if record.get("dropped"):
                    out(f"     ({len(record['dropped'])} item(s) removed by validation)")
                if record.get("reason"):
                    out(f"     reason: {record['reason']}")

        console = api_url.rstrip("/").removesuffix("/api")
        out(f"\nOpen {console}/incidents to explore the incidents in the console.")
        return 0
    except (DemoError, httpx.HTTPError, KeyError, ValueError) as exc:
        print(f"demo failed: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
