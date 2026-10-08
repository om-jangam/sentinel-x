"""Import SigmaHQ's community rules, by a rule anyone can re-run.

The shipped pack used to be assembled by hand, which made its documented "selection is reproducible"
a claim rather than a fact. This module is the claim made executable: it downloads a SigmaHQ release
package, verifies it by SHA-256, keeps **every rule this engine can evaluate**, and writes the kept files
verbatim with a manifest naming each one's upstream path.

Why "everything evaluable" and no further filter: SigmaHQ's `core` package is already its curated tier —
every rule in it is `high` or `critical` and `status: test` or `stable`, with nothing experimental and no
low-confidence hunting rules. Narrowing it further by technique, as the first import did, hid rules for
techniques the evaluation had not thought to target. What this engine cannot evaluate is refused with a
reason (an unsupported logsource, an unmapped field, a modifier that is not implemented), never
approximated — a rule that half-runs is worse than a rule that is absent, because it reports silence as
safety.

The rules are licensed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License),
which requires that the author is named wherever matches are reported; findings carry `rule_author` and
`rule_source`, and the files keep their `author` field untouched.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from app.modules.detection.infrastructure.sigma_loader import RuleLoadError, compile_sigma

SOURCE_REPOSITORY = "https://github.com/SigmaHQ/sigma"
PACKAGE = "sigma_core.zip"
DEFAULT_RELEASE = "r2026-07-01"
LICENSE_NAME = "Detection Rule License 1.1 (DRL-1.1)"
LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
# A release package is ~1.5 MB; anything far larger is not the file we asked for.
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MANIFEST = "MANIFEST.json"


class SigmaImportError(RuntimeError):
    """The package could not be fetched or is not what was asked for."""


@dataclass(slots=True)
class Selection:
    release: str
    package_sha256: str
    kept: dict[str, str] = field(default_factory=dict)  # upstream path (without "rules/") → written path
    refused: Counter[str] = field(default_factory=Counter)
    removed: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.kept) + sum(self.refused.values())


def package_url(release: str) -> str:
    return f"{SOURCE_REPOSITORY}/releases/download/{release}/{PACKAGE}"


def fetch_package(release: str, cache: Path, *, client: httpx.Client | None = None) -> Path:
    """The release package, downloaded once into `cache` and reused afterwards."""
    target = cache / release / PACKAGE
    if target.exists():
        return target
    owned = client is None
    client = client or httpx.Client(follow_redirects=True, timeout=120.0)
    try:
        response = client.get(package_url(release))
        if response.status_code != 200:
            raise SigmaImportError(f"{package_url(release)} returned HTTP {response.status_code}")
        if len(response.content) > MAX_PACKAGE_BYTES:
            raise SigmaImportError(f"{PACKAGE} is larger than {MAX_PACKAGE_BYTES} bytes")
    except httpx.HTTPError as exc:
        raise SigmaImportError(f"could not download {PACKAGE}: {exc}") from exc
    finally:
        if owned:
            client.close()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(response.content)
    return target


def _rules(archive: zipfile.ZipFile) -> Iterator[tuple[str, str]]:
    """Every rule in the package, as (path without the leading `rules/`, text)."""
    for name in sorted(archive.namelist()):
        if not name.endswith((".yml", ".yaml")) or name.endswith(MANIFEST):
            continue
        relative = name[len("rules/") :] if name.startswith("rules/") else name
        yield relative, archive.read(name).decode("utf-8")


def _reason(exc: Exception) -> str:
    return str(exc).split(": ", 1)[-1] if ": " in str(exc) else str(exc)


def select(package: Path, *, release: str, out: Path, expect_sha256: str | None = None) -> Selection:
    """Write every evaluable rule from `package` into `out`, with a manifest. Returns what was decided."""
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    if expect_sha256 is not None and digest != expect_sha256:
        raise SigmaImportError(f"{package.name} has SHA-256 {digest}, expected {expect_sha256}")
    selection = Selection(release=release, package_sha256=digest)
    out.mkdir(parents=True, exist_ok=True)
    root = out.resolve()

    with zipfile.ZipFile(package) as archive:
        written: dict[str, str] = {}
        for relative, text in _rules(archive):
            destination = out / relative
            # The package is downloaded: a rule path that climbs out of the directory is refused, not
            # written somewhere else in the repository.
            if root not in destination.resolve().parents:
                selection.refused[f"path escapes the rule directory: {relative}"] += 1
                continue
            try:
                compile_sigma(text, path=relative)
            except (RuleLoadError, ValueError) as exc:
                selection.refused[_reason(exc)] += 1
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Verbatim: the licence requires the rule, its author and its id to stay as published.
            destination.write_text(text, encoding="utf-8", newline="")
            written[relative] = f"rules/{relative}"
        selection.kept = written

    selection.removed = _prune(out, keep={out / relative for relative in written})
    (out / MANIFEST).write_text(json.dumps(_manifest(selection), indent=2) + "\n", encoding="utf-8")
    return selection


def _prune(out: Path, *, keep: set[Path]) -> list[str]:
    """Delete rule files from a previous import that this one did not select, and empty directories."""
    removed: list[str] = []
    for path in sorted(out.rglob("*.yml")) + sorted(out.rglob("*.yaml")):
        if path not in keep:
            path.unlink()
            removed.append(str(path.relative_to(out)).replace("\\", "/"))
    for directory in sorted(out.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    return removed


def _manifest(selection: Selection) -> dict[str, Any]:
    return {
        "source": SOURCE_REPOSITORY,
        "release": selection.release,
        "package": PACKAGE,
        "package_sha256": selection.package_sha256,
        "license": LICENSE_NAME,
        "license_url": LICENSE_URL,
        "rule_base_url": f"{SOURCE_REPOSITORY}/blob/{selection.release}",
        "selection": "every rule in the package that the Sentinel-X detection engine can evaluate",
        "selected": len(selection.kept),
        "files": dict(sorted(selection.kept.items())),
    }


def render_report(selection: Selection) -> str:
    """What the import decided, for the operator running it."""
    lines = [
        f"SigmaHQ {selection.release} · {PACKAGE} · sha256 {selection.package_sha256[:16]}…",
        f"  rules in package: {selection.total:,}",
        f"  selected:         {len(selection.kept):,}",
        f"  refused:          {sum(selection.refused.values()):,}",
    ]
    if selection.refused:
        lines.append("  most common reasons:")
        lines += [f"    {count:5,}  {reason[:96]}" for reason, count in selection.refused.most_common(10)]
    if selection.removed:
        lines.append(f"  removed from a previous import: {len(selection.removed):,}")
    return "\n".join(lines)


def import_rules(
    *,
    release: str = DEFAULT_RELEASE,
    cache: Path,
    out: Path,
    expect_sha256: str | None = None,
    client: httpx.Client | None = None,
) -> Selection:
    package = fetch_package(release, cache, client=client)
    return select(package, release=release, out=out, expect_sha256=expect_sha256)
