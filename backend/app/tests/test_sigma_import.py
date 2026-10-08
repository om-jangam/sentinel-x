"""The SigmaHQ import: what it keeps, what it refuses, and what it refuses to trust."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import httpx
import pytest

from app.sigma_import import (
    MANIFEST,
    PACKAGE,
    SigmaImportError,
    import_rules,
    package_url,
    render_report,
    select,
)

EVALUABLE = """
title: PowerShell with an encoded command
id: 7b1f6e2c-9a4d-4f1b-8c3e-5d2a7f0b9c18
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    CommandLine|contains: '-EncodedCommand'
  condition: sel
level: high
"""
UNSUPPORTED_LOGSOURCE = """
title: A PowerShell script block rule
id: 2c9e7a41-3b5d-4e86-9f10-7a4c2b8d5e63
status: test
logsource: {category: ps_script, product: windows}
detection:
  sel:
    ScriptBlockText|contains: 'Invoke-Mimikatz'
  condition: sel
level: high
"""
UNMAPPED_FIELD = """
title: A rule on a field no parser fills
id: 5a3c8d92-7e14-4b6f-a0d5-9c2e1b7f4a86
status: test
logsource: {product: windows, service: security}
detection:
  sel:
    ServiceFileName|contains: '\\Users\\Public\\'
  condition: sel
level: high
"""
RULES = {
    "windows/process_creation/proc_encoded.yml": EVALUABLE,
    "windows/powershell/posh_script.yml": UNSUPPORTED_LOGSOURCE,
    "windows/builtin/security/win_service.yml": UNMAPPED_FIELD,
}


def package(tmp_path: Path, rules: dict[str, str] = RULES) -> Path:
    path = tmp_path / PACKAGE
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in rules.items():
            archive.writestr(f"rules/{name}", text)
    return path


def test_every_evaluable_rule_is_kept_verbatim_and_the_rest_are_refused_by_reason(tmp_path: Path) -> None:
    out = tmp_path / "sigmahq"
    selection = select(package(tmp_path), release="r2026-07-01", out=out)

    assert set(selection.kept) == {"windows/process_creation/proc_encoded.yml"}
    kept = out / "windows/process_creation/proc_encoded.yml"
    assert kept.read_text(encoding="utf-8") == EVALUABLE, "published text, author field and id untouched"
    assert sum(selection.refused.values()) == 2
    reasons = " ".join(selection.refused)
    assert "ps_script" in reasons
    assert "ServiceFileName" in reasons


def test_the_manifest_records_the_release_the_digest_and_every_upstream_path(tmp_path: Path) -> None:
    out = tmp_path / "sigmahq"
    selection = select(package(tmp_path), release="r2026-07-01", out=out)
    manifest = json.loads((out / MANIFEST).read_text(encoding="utf-8"))

    assert manifest["release"] == "r2026-07-01"
    assert manifest["package_sha256"] == selection.package_sha256
    assert manifest["selected"] == 1
    assert manifest["files"] == {
        "windows/process_creation/proc_encoded.yml": "rules/windows/process_creation/proc_encoded.yml"
    }
    assert "Detection Rule License" in manifest["license"], "the licence the rules are under is recorded"
    assert manifest["rule_base_url"].endswith("r2026-07-01"), "so a finding can link to the rule it used"


def test_a_rule_that_is_no_longer_selected_is_removed(tmp_path: Path) -> None:
    """Re-importing must leave the directory matching the manifest, not a union of both imports."""
    out = tmp_path / "sigmahq"
    select(package(tmp_path), release="r2026-07-01", out=out)
    stale = out / "windows/process_creation/proc_gone.yml"
    stale.write_text(EVALUABLE.replace("7b1f6e2c", "0000beef"), encoding="utf-8")
    notice = out / "NOTICE.md"
    notice.write_text("the licence notice", encoding="utf-8")

    selection = select(package(tmp_path), release="r2026-07-01", out=out)

    assert not stale.exists()
    assert selection.removed == ["windows/process_creation/proc_gone.yml"]
    assert notice.read_text(encoding="utf-8") == "the licence notice", "the notice is not a rule"


def test_a_package_that_does_not_match_the_expected_digest_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "sigmahq"
    with pytest.raises(SigmaImportError, match=r"expected 0{64}"):
        select(package(tmp_path), release="r2026-07-01", out=out, expect_sha256="0" * 64)
    assert not out.exists(), "nothing unverified is written"


def test_the_package_is_downloaded_once_and_then_reused(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    body = package(source).read_bytes()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        for _ in range(2):
            import_rules(release="r2026-07-01", cache=tmp_path / "cache", out=tmp_path / "sigmahq", client=client)

    assert calls == [package_url("r2026-07-01")], "the second run reads the cached package"
    assert (tmp_path / "cache/r2026-07-01" / PACKAGE).exists()


def test_a_failed_download_says_so_rather_than_shipping_no_rules(tmp_path: Path) -> None:
    with (
        httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404))) as client,
        pytest.raises(SigmaImportError, match="returned HTTP 404"),
    ):
        import_rules(release="r9999-99-99", cache=tmp_path / "c", out=tmp_path / "o", client=client)


def test_the_report_states_what_was_decided(tmp_path: Path) -> None:
    report = render_report(select(package(tmp_path), release="r2026-07-01", out=tmp_path / "sigmahq"))
    assert "rules in package: 3" in report
    assert "selected:         1" in report
    assert "refused:          2" in report
    assert "ps_script" in report


def test_a_rule_path_that_climbs_out_of_the_directory_is_refused(tmp_path: Path) -> None:
    """The package is downloaded data: its paths decide where files land, so they are checked."""
    hostile = package(tmp_path, {"../../escaped.yml": EVALUABLE})
    out = tmp_path / "sigmahq"
    selection = select(hostile, release="r2026-07-01", out=out)

    assert selection.kept == {}
    assert [reason for reason in selection.refused] == ["path escapes the rule directory: ../../escaped.yml"]
    assert not (tmp_path.parent / "escaped.yml").exists()
    assert not (tmp_path / "escaped.yml").exists()


def test_an_empty_package_is_not_mistaken_for_a_successful_import(tmp_path: Path) -> None:
    empty = tmp_path / PACKAGE
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("rules/README.md", "no rules here")
    selection = select(empty, release="r2026-07-01", out=tmp_path / "sigmahq")
    assert selection.total == 0
    assert "selected:         0" in render_report(selection)
