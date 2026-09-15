"""Operator CLI: key generation and rotation, migrations, idempotent seeding, audit verification."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from app import cli
from app.core.config import get_settings


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
