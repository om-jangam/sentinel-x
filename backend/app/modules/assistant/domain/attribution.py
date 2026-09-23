"""Does the evidence say *who* did it? (docs/12 step 7)

Grounding by citation catches invented events, but not a statement that cites real events and attributes
the action to the wrong thing: "PowerShell connected to 192.0.2.66" when the record only shows the host
connecting. That is the mistake a small model makes most often here
([assistant results](../../../../../docs/modules/assistant.md)).

The check is deliberately narrow, because English is not evidence:

1. a claim is only recognised when the text reads *entity, relational verb, entity*, with both entities
   named in the bundle and the verb in `RELATIONS` below;
2. a passive verb ("powershell.exe **was started** by …") is skipped: its subject is its object, so the
   sentence says the opposite of what the pattern reads;
3. a claim is supported when the incident graph holds an edge between those two entities whose relation
   the verb allows — and the graph only holds edges a single stored event states;
4. anything else is left alone. A statement with no recognised claim is never flagged.

A flagged statement is **not** dropped: its citations may be fine and the wording merely loose. It is
marked, counted and shown as unverified attribution, so an analyst sees which claim to check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.modules.assistant.domain.bundle import EvidenceBundle

# verb (as written) → the graph relations that would support it. Directional unless listed in SYMMETRIC.
RELATIONS: dict[str, frozenset[str]] = {
    "connected to": frozenset({"connected_to"}),
    "connected out to": frozenset({"connected_to"}),
    "contacted": frozenset({"connected_to"}),
    "communicated with": frozenset({"connected_to"}),
    "beaconed to": frozenset({"connected_to"}),
    "reached out to": frozenset({"connected_to"}),
    "spawned": frozenset({"spawned", "started"}),
    "started": frozenset({"spawned", "started"}),
    "launched": frozenset({"spawned", "started"}),
    "executed": frozenset({"spawned", "started"}),
    "ran": frozenset({"spawned", "started", "ran_as"}),
    "opened": frozenset({"opened"}),
    "accessed": frozenset({"opened"}),
    "injected into": frozenset({"injected_into"}),
    "queried": frozenset({"queried"}),
    "resolved to": frozenset({"resolved_to"}),
    "logged on to": frozenset({"logon", "logon_as"}),
    "logged onto": frozenset({"logon", "logon_as"}),
    "logged into": frozenset({"logon", "logon_as"}),
    "authenticated to": frozenset({"logon", "logon_as"}),
    "failed to log on to": frozenset({"failed_logon", "failed_logon_as"}),
    "wrote": frozenset({"file_activity"}),
    "created": frozenset({"file_activity", "spawned", "started"}),
}
# Relations where the record fixes no order (a logon involves an address, a host and an account alike).
SYMMETRIC = frozenset({"logon", "logon_as", "failed_logon", "failed_logon_as", "ran_as", "file_activity"})
MAX_CLAIMS = 3
MIN_VALUE = 3  # shorter entity values (a one-letter user name) match too much prose to be reliable
# When one word names several entities — `powershell.exe` is both a process and its file — the claim is
# about the actor, not the file on disk. Lower sorts first.
KIND_ORDER = {"process": 0, "host": 1, "user": 2, "ip": 3, "domain": 4, "file": 5, "hash": 6}
_PASSIVE = re.compile(r"\b(?:was|were|is|are|been|being|be)\s+(?:\w+\s+){0,2}$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Claim:
    subject: str  # entity key, e.g. "process:powershell.exe"
    verb: str
    target: str
    supported: bool

    def describe(self) -> str:
        return f"{self.subject.split(':', 1)[1]} {self.verb} {self.target.split(':', 1)[1]}"


def aliases(key: str) -> list[str]:
    """How a model is likely to write this entity: `powershell.exe` is usually just "PowerShell"."""
    kind, _, value = key.partition(":")
    if not value:
        kind, value = "", key
    found = [value]
    if kind in {"process", "file"} and "." in value:
        found.append(value.rsplit(".", 1)[0].rsplit("\\", 1)[-1])
    if kind == "host" and "." in value:
        found.append(value.split(".", 1)[0])
    if kind == "user" and "\\" in value:
        found.append(value.rsplit("\\", 1)[1])
    return [item for item in dict.fromkeys(found) if len(item) >= MIN_VALUE]


def _mentions(text: str, entities: list[str]) -> list[tuple[int, int, str]]:
    """Where each entity is named, longest spelling first so `corp\\jsmith` wins over `jsmith`."""
    lowered = text.lower()
    spellings = sorted(
        ((alias, key) for key in entities for alias in aliases(key)),
        key=lambda pair: (-len(pair[0]), KIND_ORDER.get(pair[1].split(":", 1)[0], 9), pair[1]),
    )
    found: list[tuple[int, int, str]] = []
    for alias, key in spellings:
        for match in re.finditer(rf"(?<![\w.\\]){re.escape(alias.lower())}(?![\w])", lowered):
            if not any(start < match.end() and match.start() < end for start, end, _ in found):
                found.append((match.start(), match.end(), key))
    return sorted(found)


def claims(text: str, bundle: EvidenceBundle) -> list[Claim]:
    """Every *entity verb entity* claim the text makes, and whether the graph states it."""
    mentions = _mentions(text, bundle.entities)
    if len(mentions) < 2:
        return []
    lowered = text.lower()
    # `name` is the relation's own name ("connected_to"); `relation` is the label the model reads
    # ("connected to"). Comparing against the label silently matched almost nothing.
    edges = {(edge.source, edge.name or edge.relation, edge.target) for edge in bundle.graph}

    found: list[Claim] = []
    for verb, relations in RELATIONS.items():
        for match in re.finditer(rf"(?<!\w){re.escape(verb)}(?!\w)", lowered):
            if _PASSIVE.search(lowered[: match.start()]):
                continue
            before = [key for start, _, key in mentions if start < match.start()]
            after = [key for start, _, key in mentions if start >= match.end()]
            if not before or not after:
                continue
            subject, target = before[-1], after[0]
            if subject == target:
                continue
            supported = any(
                (subject, relation, target) in edges or (relation in SYMMETRIC and (target, relation, subject) in edges)
                for relation in relations
            )
            found.append(Claim(subject, verb, target, supported))
            if len(found) >= MAX_CLAIMS:
                return found
    return found


def unsupported(text: str, bundle: EvidenceBundle) -> str | None:
    """The reason to show when a statement claims a relationship no single event states."""
    unproven = [claim for claim in claims(text, bundle) if not claim.supported]
    if not unproven:
        return None
    return "no event states " + "; ".join(claim.describe() for claim in unproven)
