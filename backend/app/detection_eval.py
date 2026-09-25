"""Detection measured on public attack recordings (docs/12, step 2).

Replays Windows event logs recorded while real attack techniques ran, through the real parsers and the real
detection engine (`DetectionService` with in-memory storage), and reports per ATT&CK technique whether any
shipped rule flagged it.

**Which recordings.** All come from [splunk/attack_data](https://github.com/splunk/attack_data) (Apache 2.0),
downloaded at evaluation time and checked against the SHA-256 in the repository's Git LFS pointer. They are
never committed. Two sets, chosen by fixed rules rather than by what Sentinel-X happens to catch:

- **priority**: Red Canary's Threat Detection Report top-10 techniques that Windows event logs can show
  (the cloud and email ones have no such logs), using each technique's `atomic_red_team` recording;
- **claims**: every technique a shipped rule claims to detect, to check the claim on data nobody wrote for
  Sentinel-X. Where there is no `atomic_red_team` recording, the folder holding Windows event logs is used.

Within a folder, the files are the Sysmon log and, if present, `windows-security.log`.

**What counts as detected.** A finding whose technique is the recording's technique, its parent (a T1110
rule on a T1110.003 recording) or one of its sub-techniques, **citing at least one event that is not the
test lab's own automation**. Findings for other techniques are listed separately: an Atomic Red Team run also
does setup and cleanup, so they are not false positives by default.

**Test-lab automation.** Splunk's Attack Range drives each test from Ansible over WinRM, which itself runs
encoded PowerShell. A rule for encoded PowerShell therefore fires on the harness in every recording. An event
is treated as harness activity only when its command line, or the text its `-EncodedCommand` decodes to,
contains one of `HARNESS_MARKERS`: fixed strings from Ansible's WinRM exec wrapper and the Atomic Red Team
runner, never anything a test itself runs. Harness findings are reported, not counted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, NamedTuple, Self
from uuid import UUID

import httpx
from pydantic import ValidationError

from app.core.events.bus import Event
from app.core.events.topics import EVENTS_NORMALIZED
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import ParseError, UnsupportedEventError, normalize
from app.ingest_pipeline.wineventlog_text import iter_records as iter_rendered
from app.ingest_pipeline.winxml import WindowsXmlError, iter_events
from app.modules.detection.application.detection_service import DetectionService
from app.modules.detection.domain.findings import Finding
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore

SOURCE_REPOSITORY = "https://github.com/splunk/attack_data"
DOWNLOAD_BASE = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/"
DEFAULT_CACHE = Path(__file__).resolve().parents[1] / ".cache" / "detection-datasets"
ORG = UUID("00000000-0000-7000-8000-00000000e7a1")
BATCH = 500

# Strings that identify the test lab's automation (see the module docstring). Each was seen in the
# recordings' decoded command lines; none is part of any Atomic Red Team test's own command.
HARNESS_MARKERS = (
    "$exec_wrapper",  # Ansible's PowerShell exec wrapper
    "Reboot initiated by Ansible",
    "(Get-WmiObject -ClassName Win32_OperatingSystem).LastBootUpTime",  # Ansible's reboot/uptime check
    'Import-Module "C:\\AtomicRedTeam',  # the Invoke-AtomicTest runner loading itself
    "PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand",  # Ansible's launch line
    "[Console]::InputEncoding = New-Object Text.UTF8Encoding $false;",  # Attack Range's command prefix
)
# PowerShell accepts any prefix of -EncodedCommand (-e, -en, -enc, …), with - or /.
# The value can't start with - or /, or the next switch would be read as Base64 ("/" is a Base64 character).
_SWITCH_ARGUMENT = re.compile(r"(?i)(?:^|\s)[-/]([a-z]+)\s+\"?([A-Za-z0-9+=][A-Za-z0-9+/=]{7,})")

CHANNEL_PARSERS = {
    "Security": "windows_security",
    "Microsoft-Windows-Sysmon/Operational": "windows_sysmon",
    "Microsoft-Windows-NTLM/Operational": "windows_ntlm",
}


@dataclass(frozen=True, slots=True)
class DatasetFile:
    path: str  # relative to datasets/attack_techniques/
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class Dataset:
    technique: str
    name: str
    purpose: str  # "priority" or "claims"
    files: tuple[DatasetFile, ...]


@dataclass(frozen=True, slots=True)
class Unavailable:
    technique: str
    name: str
    purpose: str
    reason: str


def _f(path: str, sha256: str, size: int) -> DatasetFile:
    return DatasetFile(path, sha256, size)


DATASETS: tuple[Dataset, ...] = (
    Dataset(
        "T1059.001",
        "PowerShell",
        "priority",
        (
            _f(
                "T1059.001/atomic_red_team/windows-sysmon.log",
                "8f71b2a0ef81892551cd6a9ad115b8ec5c42d9f2071547b064c496511898c4e9",
                38_928_903,
            ),
            _f(
                "T1059.001/atomic_red_team/windows-security.log",
                "aed5d2956ff35417d5b971b45d84004f8e8361db3e2c8924b96f3bd0ed57bfb9",
                593_281,
            ),
        ),
    ),
    Dataset(
        "T1059.003",
        "Windows Command Shell",
        "priority",
        (
            _f(
                "T1059.003/atomic_red_team/sqlcmd_windows_sysmon.log",
                "e6f50e00a97eab28fe6d3d0f2ee99b5979a7214797d4380784d1bafaddb77d25",
                16_495,
            ),
        ),
    ),
    Dataset(
        "T1105",
        "Ingress Tool Transfer",
        "priority",
        (
            _f(
                "T1105/atomic_red_team/windows-sysmon.log",
                "bd6bbf7884f44274988d159bcb3249505dc53623e551892b54a3fc87db06e18c",
                3_625_178,
            ),
            _f(
                "T1105/atomic_red_team/windows-security.log",
                "0859fc0fea16337fefe20962fa152d8a6f39e8cbb6a016da13d4f9a4d88d234f",
                200_829,
            ),
        ),
    ),
    Dataset(
        "T1047",
        "Windows Management Instrumentation",
        "priority",
        (
            _f(
                "T1047/atomic_red_team/windows-sysmon.log",
                "64651720e10813aa57d0f25ce149005ab06039b1974dbc09818b1fb45fbbc196",
                11_815_541,
            ),
            _f(
                "T1047/atomic_red_team/windows-security.log",
                "51b50514a9599a0f4ea879b08956a372ed1f182edd68185b1734d228ebcd4df8",
                7_323_827,
            ),
        ),
    ),
    Dataset(
        "T1027",
        "Obfuscated Files or Information",
        "priority",
        (
            _f(
                "T1027/atomic_red_team/windows-sysmon.log",
                "43562f5040d3c1ec604fe917d6aaec43c8a48c073a3c49e439326e28845e5c38",
                11_316_256,
            ),
            _f(
                "T1027/atomic_red_team/windows-security.log",
                "3a8d701af4ee1b87f25699340647a07252061772857da5cf5e6501695074a9ac",
                5_978_290,
            ),
        ),
    ),
    Dataset(
        "T1033",
        "System Owner/User Discovery",
        "claims",
        (
            _f(
                "T1033/atomic_red_team/windows-sysmon.log",
                "7dc221cd808a62738dbe28d8eb1c3ba7d653d8098b82f745dfc18181148978b2",
                11_994_992,
            ),
            _f(
                "T1033/atomic_red_team/windows-security.log",
                "a62767660239a12d50057fc2f0598ff2d87a4c80f67606cd3b8673ed3381d599",
                6_175_387,
            ),
        ),
    ),
    Dataset(
        "T1069.002",
        "Domain Groups",
        "claims",
        (
            _f(
                "T1069.002/AD_discovery/windows-sysmon.log",
                "4372514fa4f0ef23f31e22a050be452392756165077abad62297ad2475143146",
                4_933_425,
            ),
            _f(
                "T1069.002/AD_discovery/windows-security.log",
                "843261d058cedd3034b69395a9b18db7bcf85f650aaf927f6394a8ed97298d39",
                322_389,
            ),
        ),
    ),
    Dataset(
        "T1110.003",
        "Password Spraying",
        "claims",
        (
            _f(
                "T1110.003/ntlm_bruteforce/ntlm_bruteforce.log",
                "63a209ac79763e9a54a69559d35e33d848b430dbc719c6ca9258409f34c24aea",
                404_012,
            ),
        ),
    ),
)

UNAVAILABLE: tuple[Unavailable, ...] = (
    Unavailable(
        "T1204.004",
        "Malicious Copy and Paste",
        "priority",
        "no recording in splunk/attack_data",
    ),
    Unavailable(
        "T1071",
        "Application Layer Protocol",
        "claims",
        "no Windows event log recording (the T1071.001 folders hold proxy and web logs)",
    ),
)


# ------------------------------------------------------------------ download


class DatasetIntegrityError(RuntimeError):
    """A downloaded file is not the one the manifest names."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached(file: DatasetFile, cache: Path) -> Path:
    return cache / file.path


async def fetch(
    datasets: Iterable[Dataset], cache: Path, *, client: httpx.AsyncClient | None = None
) -> list[tuple[DatasetFile, str]]:
    """Download what isn't cached yet; every file is checked against its SHA-256. Returns (file, outcome)."""
    owned = client is None
    http = client or httpx.AsyncClient(timeout=httpx.Timeout(60.0), follow_redirects=True)
    outcomes: list[tuple[DatasetFile, str]] = []
    try:
        for dataset in datasets:
            for file in dataset.files:
                target = cached(file, cache)
                if target.exists() and _sha256(target) == file.sha256:
                    outcomes.append((file, "cached"))
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                partial = target.with_suffix(target.suffix + ".part")
                digest, written = hashlib.sha256(), 0
                async with http.stream("GET", DOWNLOAD_BASE + file.path) as response:
                    response.raise_for_status()
                    with partial.open("wb") as handle:
                        async for chunk in response.aiter_bytes():
                            written += len(chunk)
                            if written > file.size:
                                break
                            digest.update(chunk)
                            handle.write(chunk)
                if written != file.size or digest.hexdigest() != file.sha256:
                    partial.unlink(missing_ok=True)
                    raise DatasetIntegrityError(f"{file.path}: downloaded content does not match its SHA-256")
                partial.replace(target)
                outcomes.append((file, "downloaded"))
    finally:
        if owned:
            await http.aclose()
    return outcomes


# ------------------------------------------------------------------ replay


class _Findings:
    def __init__(self) -> None:
        self.by_key: dict[str, Finding] = {}

    async def add(self, finding: Finding) -> bool:
        if finding.dedupe_key in self.by_key:
            return False
        self.by_key[finding.dedupe_key] = finding
        return True

    async def get(self, org_id: UUID, finding_id: UUID) -> Finding | None:
        return next((f for f in self.by_key.values() if f.id == finding_id), None)

    async def get_by_dedupe_key(self, org_id: UUID, dedupe_key: str) -> Finding | None:
        return self.by_key.get(dedupe_key)

    async def search(self, org_id: UUID, query: Any) -> Any:  # pragma: no cover - not used offline
        raise NotImplementedError


class _UnitOfWork:
    def __init__(self, findings: _Findings) -> None:
        self.findings = findings

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def technique_matches(finding_technique: str, label: str) -> bool:
    """Same technique, its parent, or one of its sub-techniques."""
    finding, label = finding_technique.upper(), label.upper()
    return finding == label or label.startswith(finding + ".") or finding.startswith(label + ".")


@dataclass(slots=True)
class DatasetResult:
    dataset: Dataset
    events: int = 0
    channels: Counter[str] = field(default_factory=Counter)
    accepted: int = 0
    rejected: Counter[str] = field(default_factory=Counter)
    unsupported: Counter[str] = field(default_factory=Counter)
    unread_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    harness_events: set[str] = field(default_factory=set)

    def is_harness(self, finding: Finding) -> bool:
        return all(uid in self.harness_events for uid in finding.evidence)

    @property
    def harness(self) -> list[Finding]:
        return [f for f in self.findings if self.is_harness(f)]

    @property
    def matching(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if not self.is_harness(f) and any(technique_matches(t, self.dataset.technique) for t in f.techniques)
        ]

    @property
    def detected(self) -> bool:
        return bool(self.matching)

    @property
    def other(self) -> list[Finding]:
        return [f for f in self.findings if f not in self.matching and not self.is_harness(f)]


def _decoded(command_line: str) -> str:
    """The text an `-EncodedCommand` argument decodes to (UTF-16LE Base64), or "" if there is none."""
    for switch, value in _SWITCH_ARGUMENT.findall(command_line):
        if not "encodedcommand".startswith(switch.lower()):
            continue
        try:
            return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-16-le", errors="ignore")
        except (binascii.Error, ValueError):
            return ""
    return ""


def is_harness_command(command_line: str) -> bool:
    # Whitespace is collapsed: the harness sometimes writes "PowerShell  -NoProfile" with two spaces.
    text = " ".join(f"{command_line}\n{_decoded(command_line)}".split())
    return any(marker in text for marker in HARNESS_MARKERS)


def _reason(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        return f"invalid OCSF: {location} {first.get('msg', '')}".strip()
    return str(exc)[:120]


class _Read(NamedTuple):
    """One event a reader recovered from a file: its channel, and the record the parsers read."""

    channel: str | None
    record: dict[str, Any]


def _read(text: str) -> tuple[list[_Read | Exception], str] | None:
    """Every event in a file, using whichever reader fits it. None if neither recognises the file."""
    xml = list(iter_events(text))  # raises WindowsXmlError only when the whole file is refused
    if xml:
        return ([item if isinstance(item, Exception) else _Read(item.channel, item.record) for item in xml], "XML")
    # No XML: try Splunk's rendered WinEventLog text, which names its channel in the header.
    rendered: list[_Read | Exception] = [
        item if isinstance(item, Exception) else _Read(item.pop("Channel", None), item) for item in iter_rendered(text)
    ]
    return (rendered, "rendered text") if rendered else None


def _documents(result: DatasetResult, files: Iterable[tuple[str, str]], *, source_id: str) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    ingested_at = datetime.now(UTC)
    for name, text in files:
        try:
            read = _read(text)
        except WindowsXmlError as exc:
            result.unread_files.append(f"{name}: refused ({exc})")
            continue
        if read is None:
            # Not silently zero: say the file held nothing either reader understands.
            result.unread_files.append(f"{name}: neither Windows event XML nor rendered WinEventLog text")
            continue
        items, form = read
        for item in items:
            result.events += 1
            if isinstance(item, Exception):
                result.rejected[f"unreadable {form}: {item}"[:120]] += 1
                continue
            channel = item.channel or "(none)"
            result.channels[channel] += 1
            parser = CHANNEL_PARSERS.get(channel)
            if parser is None:
                continue  # another log (System, PowerShell, …): not a source Sentinel-X parses
            try:
                event = normalize(parser, item.record)
            except UnsupportedEventError as exc:
                result.unsupported[str(exc)] += 1
                continue
            except (ParseError, ValidationError) as exc:
                result.rejected[_reason(exc)] += 1
                continue
            result.accepted += 1
            uid = event_uid_for(event.fingerprint(org_id=str(ORG), source_id=source_id))
            if event.process is not None and event.process.cmd_line and is_harness_command(event.process.cmd_line):
                result.harness_events.add(uid)
            documents.append(
                event.to_document(org_id=str(ORG), source_id=source_id, event_uid=uid, ingested_at=ingested_at)
            )
    documents.sort(key=lambda document: (document["time"], document["sx"]["event_uid"]))
    return documents


async def replay(dataset: Dataset, files: Sequence[tuple[str, str]]) -> DatasetResult:
    """Run one recording through the parsers and the shipped rules, with fresh state."""
    result = DatasetResult(dataset)
    findings = _Findings()
    service = DetectionService(
        load_rules(), uow_factory=lambda: _UnitOfWork(findings), windows=InMemoryWindowStore(max_keys=100_000)
    )
    documents = _documents(result, files, source_id=f"eval-{dataset.technique}")
    for start in range(0, len(documents), BATCH):
        payload = {"documents": [{"body": document} for document in documents[start : start + BATCH]]}
        await service.handle(Event(topic=EVENTS_NORMALIZED, payload=payload, org_id=ORG))
    result.findings = sorted(findings.by_key.values(), key=lambda f: (f.first_seen, f.rule_title))
    return result


async def evaluate(datasets: Iterable[Dataset], cache: Path) -> list[DatasetResult]:
    results = []
    for dataset in datasets:
        files = []
        for file in dataset.files:
            path = cached(file, cache)
            if not path.exists():
                raise FileNotFoundError(f"{path} is missing: run `sentinelx fetch-detection-datasets` first")
            files.append((file.path, path.read_text(encoding="utf-8", errors="replace")))
        results.append(await replay(dataset, files))
    return results


# ------------------------------------------------------------------ report


def _score(results: Sequence[DatasetResult], purpose: str) -> str:
    chosen = [r for r in results if r.dataset.purpose == purpose]
    missing = [u for u in UNAVAILABLE if u.purpose == purpose]
    detected = sum(r.detected for r in chosen)
    return f"{detected} of {len(chosen)} recorded techniques" + (
        f" ({len(missing)} more {'has' if len(missing) == 1 else 'have'} no public recording)" if missing else ""
    )


def render_report(results: Sequence[DatasetResult], *, rule_count: int, generated: datetime) -> str:
    lines = [
        "# Detection on public attack recordings",
        "",
        f"*Generated by `sentinelx evaluate-detection` on {generated:%Y-%m-%d} with {rule_count} shipped rules.* "
        "Method and dataset choice: [`app/detection_eval.py`](../../backend/app/detection_eval.py) and "
        "[docs/12](../12-improvement-research.md#2-measure-detection-on-public-attack-recordings).",
        "",
        f"Recordings: [splunk/attack_data]({SOURCE_REPOSITORY}) (Apache 2.0), downloaded and verified by "
        "SHA-256, never committed.",
        "",
        "## Summary",
        "",
        f"- **Industry priority** (Red Canary top-10, Windows-observable): {_score(results, 'priority')} detected.",
        f"- **Claims check** (techniques a shipped rule claims): {_score(results, 'claims')} detected.",
        "",
        "Events are counted as **parsed** when they became OCSF, **unmapped** when they are an event type "
        "no parser maps (most of a Windows Security log is audit types no rule reads), and **rejected** when "
        "a record Sentinel-X should read could not be read.",
        "",
        "| Technique | Set | Events read | Parsed | Unmapped type | Rejected | Detected | By |",
        "|-----------|-----|-------------|--------|---------------|----------|----------|----|",
    ]
    for r in results:
        rules = sorted({f.rule_title for f in r.matching})
        lines.append(
            f"| {r.dataset.technique} {r.dataset.name} | {r.dataset.purpose} | {r.events:,} | {r.accepted:,} | "
            f"{sum(r.unsupported.values()):,} | {sum(r.rejected.values()):,} | "
            f"{'yes' if r.detected else '**no**'} | {'; '.join(rules) or '—'} |"
        )
    for u in UNAVAILABLE:
        lines.append(f"| {u.technique} {u.name} | {u.purpose} | — | — | — | — | not measured | {u.reason} |")

    lines += ["", "## Per recording", ""]
    for r in results:
        lines += [f"### {r.dataset.technique} {r.dataset.name}", ""]
        lines.append("Files: " + ", ".join(f"`{f.path}`" for f in r.dataset.files))
        lines.append("")
        channels = ", ".join(f"{name} {count:,}" for name, count in r.channels.most_common())
        lines.append(f"- Events by log: {channels or 'none'}")
        for unread in r.unread_files:
            lines.append(f"- **Not read:** `{unread}`")
        if r.unsupported:
            lines.append(
                "- Event types no parser maps (most common): "
                + "; ".join(f"{reason}: {n:,}" for reason, n in r.unsupported.most_common(5))
            )
        if r.rejected:
            lines.append(
                "- Not parsed (most common): "
                + "; ".join(f"{reason}: {n:,}" for reason, n in r.rejected.most_common(5))
            )
        lines.append(
            "- Findings for this technique: "
            + (", ".join(f"{t}: {n}" for t, n in Counter(f.rule_title for f in r.matching).most_common()) or "none")
        )
        harness = Counter(f.rule_title for f in r.harness)
        lines.append(
            "- Test-lab automation (not counted): "
            + (", ".join(f"{t}: {n}" for t, n in harness.most_common()) or "none")
        )
        lines.append(
            "- Other findings: "
            + (
                ", ".join(
                    f"{t} ({', '.join(sorted({x for f in r.other if f.rule_title == t for x in f.techniques}))}): {n}"
                    for t, n in Counter(f.rule_title for f in r.other).most_common()
                )
                or "none"
            )
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
