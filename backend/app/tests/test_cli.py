"""Operator CLI: keys, migrations, idempotent seeding, audit verification, OpenAPI export, demo loading."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app import cli
from app.core.config import get_settings
from app.modules.ingestion.domain.events import EventDocument, IndexOutcome


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("SENTINELX_DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'cli.db').as_posix()}")
    monkeypatch.setenv("SENTINELX_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("SENTINELX_ARGON2_MEMORY_COST_KIB", "64")
    monkeypatch.setenv("SENTINELX_ARGON2_PARALLELISM", "1")
    monkeypatch.delenv("SENTINELX_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def test_generate_keys_refuses_overwrite_and_keeps_previous_key_on_rotation(tmp_path: Path) -> None:
    out = tmp_path / "secrets"
    assert cli.main(["generate-keys", "--out", str(out)]) == 0
    assert (out / "jwt_private.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    first_public = (out / "jwt_public.pem").read_bytes()

    assert cli.main(["generate-keys", "--out", str(out)]) == 1, "must not silently replace a live key"

    assert cli.main(["generate-keys", "--out", str(out), "--force"]) == 0
    assert (out / "jwt_previous_public.pem").read_bytes() == first_public
    assert (out / "jwt_public.pem").read_bytes() != first_public


def test_migrate_seed_verify(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["migrate"]) == 0
    assert "sentinelx seed" in capsys.readouterr().out, "migrate points at the permission sync"

    assert cli.main(["seed", "--admin-email", "ops@example.com"]) == 1, "no password available"

    monkeypatch.setenv("SENTINELX_BOOTSTRAP_ADMIN_PASSWORD", "short")
    assert cli.main(["seed", "--admin-email", "ops@example.com"]) == 1, "weak password rejected"
    assert "at least 12 characters" in capsys.readouterr().err

    monkeypatch.setenv("SENTINELX_BOOTSTRAP_ADMIN_PASSWORD", "a-strong-bootstrap-passphrase")
    assert cli.main(["seed", "--admin-email", "ops@example.com"]) == 0
    assert "created admin ops@example.com" in capsys.readouterr().out
    assert cli.main(["seed", "--admin-email", "ops@example.com"]) == 0
    assert "already exists" in capsys.readouterr().out

    assert cli.main(["verify-audit"]) == 0
    reports = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(reports) == 1
    assert reports[0]["valid"] is True
    assert reports[0]["entries_checked"] > 0


def test_export_openapi(tmp_path: Path) -> None:
    out = tmp_path / "openapi.json"
    assert cli.main(["export-openapi", "--out", str(out)]) == 0
    spec = json.loads(out.read_text(encoding="utf-8"))
    assert {"/api/v1/auth/login", "/api/v1/users", "/api/v1/audit/verify"} <= set(spec["paths"])


class RecordingStore:
    """Stands in for OpenSearch: keeps the first copy of each fingerprint, like `create` does."""

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    async def ensure_ready(self) -> None:
        return None

    async def index(self, documents: Sequence[EventDocument]) -> IndexOutcome:
        new = [document for document in documents if document.id not in self.documents]
        for document in new:
            self.documents[document.id] = dict(document.body)
        return IndexOutcome(indexed=len(new), duplicates=len(documents) - len(new), failed=0)

    async def get_many(self, org_id: Any, event_uids: Sequence[str]) -> dict[str, dict[str, Any]]:
        wanted = set(event_uids)
        return {d["sx"]["event_uid"]: d for d in self.documents.values() if d["sx"]["event_uid"] in wanted}

    async def aclose(self) -> None:
        return None


def _at(document: dict[str, Any]) -> datetime:
    return datetime.strptime(document["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def test_load_demo_ingests_the_sample_attack_story(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["migrate"]) == 0
    assert cli.main(["seed"]) == 0
    store = RecordingStore()
    monkeypatch.setattr(
        "app.modules.ingestion.infrastructure.opensearch_store.event_store_from_settings", lambda _settings: store
    )
    capsys.readouterr()

    assert cli.main(["load-demo"]) == 0
    assert "loaded 33 events (1 records skipped)" in capsys.readouterr().out
    documents = list(store.documents.values())
    assert len(documents) == 33

    newest = max(map(_at, documents))
    assert timedelta(minutes=4) < datetime.now(UTC) - newest < timedelta(minutes=6)

    # One shift for all files: the Windows PowerShell launch still precedes the DNS lookup by ~62 s.
    powershell = next(d for d in documents if d.get("process", {}).get("name") == "powershell.exe")
    dns = next(d for d in documents if d["class_uid"] == 4003)
    gap = (_at(dns) - _at(powershell)).total_seconds()
    assert 62 <= gap <= 63

    # Re-running reuses the demo sources and never stores the same record twice.
    assert cli.main(["load-demo", "--keep-timestamps"]) == 0
    stored = len(store.documents)
    assert cli.main(["load-demo", "--keep-timestamps"]) == 0
    assert len(store.documents) == stored


def _count(cli_env: Path, table: str) -> int:
    with sqlite3.connect(cli_env / "cli.db") as connection:
        count: int = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608 - fixed names
    return count


def test_load_demo_runs_detection_and_correlation(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Demo data must take the same path as live data: without it the demo shows no findings or incidents."""
    assert cli.main(["migrate"]) == 0
    assert cli.main(["seed"]) == 0
    capsys.readouterr()

    assert cli.main(["load-demo"]) == 0
    output = capsys.readouterr()
    assert "SENTINELX_OPENSEARCH_URL is not set" in output.err, "no event store: say so, but still analyse"
    assert "detection and correlation ran in-process" in output.out
    assert _count(cli_env, "findings") == 12
    assert _count(cli_env, "incidents") == 2
    assert _count(cli_env, "incident_events") == 22

    # Loading again adds nothing: the same records produce the same event_uids and findings.
    assert cli.main(["load-demo", "--keep-timestamps"]) == 0
    assert cli.main(["load-demo", "--keep-timestamps"]) == 0
    assert _count(cli_env, "findings") == 24, "the original dates are a separate, second story"
    assert _count(cli_env, "incidents") == 4


def test_load_demo_needs_the_samples(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["migrate"]) == 0
    assert cli.main(["seed"]) == 0
    capsys.readouterr()
    assert cli.main(["load-demo", "--samples", str(cli_env / "missing")]) == 1
    assert "sample telemetry not found" in capsys.readouterr().err
