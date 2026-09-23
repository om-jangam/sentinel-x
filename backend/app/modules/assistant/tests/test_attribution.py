"""Attribution: a statement may cite real events and still say the wrong thing did it."""

from __future__ import annotations

import pytest

from app.modules.assistant.domain.attribution import claims, unsupported
from app.modules.assistant.domain.bundle import BundleEdge, EvidenceBundle

HOST = "host:ws-fin-07"
PROCESS = "process:powershell.exe"
PARENT = "process:winword.exe"
REMOTE = "ip:192.0.2.66"
USER = "user:corp\\jsmith"
DOMAIN = "domain:update.bad.example"


def bundle(*edges: tuple[str, str, str]) -> EvidenceBundle:
    """A bundle with only what this check reads: the entities and the graph edges events state."""
    return EvidenceBundle(
        incident={},
        findings=[],
        links=[],
        events=[],
        timeline=[],
        # As the real bundle carries them: the label the model reads, plus the relation's own name.
        graph=[
            BundleEdge(source=s, relation=r.replace("_", " "), target=t, events=["e1"], name=r) for s, r, t in edges
        ],
        intel=[],
        entities=[HOST, PROCESS, PARENT, REMOTE, USER, DOMAIN],
    )


HOST_CONNECTED = bundle((HOST, "connected_to", REMOTE), (PARENT, "spawned", PROCESS), (HOST, "ran_as", USER))


def test_the_mistake_this_exists_for() -> None:
    """The host connected out; the record never says PowerShell did."""
    reason = unsupported("PowerShell connected to 192.0.2.66 every 60 seconds.", HOST_CONNECTED)
    assert reason == "no event states powershell.exe connected to 192.0.2.66"


def test_the_same_claim_passes_when_an_event_states_it() -> None:
    with_process = bundle((PROCESS, "connected_to", REMOTE))
    assert unsupported("PowerShell connected to 192.0.2.66 every 60 seconds.", with_process) is None


@pytest.mark.parametrize(
    "text",
    [
        "ws-fin-07 connected to 192.0.2.66.",  # the edge the events state
        "WINWORD.EXE spawned powershell.exe.",
        "winword.exe started powershell.exe.",  # a verb the same relation allows
        "corp\\jsmith ran processes on ws-fin-07.",  # ran_as, which has no fixed order
        "ws-fin-07 ran as corp\\jsmith.",
    ],
)
def test_supported_claims_are_not_flagged(text: str) -> None:
    assert unsupported(text, HOST_CONNECTED) is None


@pytest.mark.parametrize(
    "text",
    [
        "The incident begins with repeated failures and a successful logon.",  # names no two entities
        "powershell.exe was started with an encoded command on ws-fin-07.",  # no relational verb between them
        "192.0.2.66 is not known to threat intelligence.",
        "ws-fin-07 shows powershell.exe activity worth reviewing.",
    ],
)
def test_statements_without_a_relationship_claim_are_left_alone(text: str) -> None:
    assert unsupported(text, HOST_CONNECTED) is None


def test_direction_matters_for_relations_that_have_one() -> None:
    reason = unsupported("powershell.exe spawned WINWORD.EXE.", HOST_CONNECTED)
    assert reason == "no event states powershell.exe spawned winword.exe"


def test_a_claim_about_an_entity_the_incident_does_not_have_is_ignored() -> None:
    """Unknown names are already handled by the mention check; this one must not guess."""
    assert unsupported("explorer.exe connected to 192.0.2.66.", HOST_CONNECTED) is None


def test_several_claims_are_reported_together() -> None:
    reason = unsupported(
        "powershell.exe connected to 192.0.2.66 and powershell.exe spawned WINWORD.EXE.", HOST_CONNECTED
    )
    assert reason is not None
    assert "powershell.exe connected to 192.0.2.66" in reason
    assert "powershell.exe spawned winword.exe" in reason


def test_claims_report_what_was_checked() -> None:
    found = claims("WINWORD.EXE spawned powershell.exe, which connected to 192.0.2.66.", HOST_CONNECTED)
    assert [(c.subject, c.verb, c.target, c.supported) for c in found] == [
        (PROCESS, "connected to", REMOTE, False),
        (PARENT, "spawned", PROCESS, True),
    ]


def test_dns_and_logon_wording() -> None:
    dns = bundle((HOST, "queried", DOMAIN), ("ip:198.51.100.23", "logon", HOST))
    dns.entities.append("ip:198.51.100.23")
    assert unsupported("ws-fin-07 queried update.bad.example.", dns) is None
    assert unsupported("198.51.100.23 logged on to ws-fin-07.", dns) is None
    assert unsupported("powershell.exe queried update.bad.example.", dns) is not None
