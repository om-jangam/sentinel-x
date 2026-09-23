"""The attribution check against a bundle built by the real pipeline, not a hand-made one.

Unit tests build `BundleEdge`s by hand and can agree with themselves while disagreeing with reality: the
first version of this check compared against the relation's *label* ("connected to") where the bundle
carries its *name* ("connected_to"), so it silently flagged true statements and passed its own tests.
These tests use the sample incidents exactly as the assistant sees them.
"""

from __future__ import annotations

import pytest

from app.assistant_eval import sample_bundles
from app.modules.assistant.domain.attribution import claims, unsupported
from app.modules.assistant.domain.bundle import EvidenceBundle


@pytest.fixture(scope="module")
async def bundle() -> EvidenceBundle:
    return (await sample_bundles())["ws-fin-07"]


async def test_the_bundle_carries_both_the_label_and_the_relation_name(bundle: EvidenceBundle) -> None:
    edge = next(edge for edge in bundle.graph if edge.name == "connected_to")
    assert edge.relation == "connected to", "the label is what the model reads"
    assert edge.source == "host:ws-fin-07"
    assert edge.target == "ip:192.0.2.66"


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        # The host connected out; the Windows Security log never names the process that did.
        ("PowerShell connected to 192.0.2.66 every 60 seconds.", True),
        ("ws-fin-07 connected to 192.0.2.66 every 60 seconds.", False),
        ("explorer.exe spawned powershell.exe with an encoded command.", False),
        ("powershell.exe spawned explorer.exe.", True),
        ("198.51.100.23 logged on to ws-fin-07 after repeated failures.", False),
        ("acme\\jsmith ran processes on ws-fin-07.", False),
        ("The activity looks like a beacon to a command and control server.", False),
    ],
)
async def test_claims_are_judged_against_what_the_events_state(
    bundle: EvidenceBundle, text: str, flagged: bool
) -> None:
    assert (unsupported(text, bundle) is not None) is flagged


async def test_a_process_name_means_the_process_not_its_file(bundle: EvidenceBundle) -> None:
    """`powershell.exe` is both a process and a file in this bundle; a claim is about the actor."""
    [claim] = claims("PowerShell connected to 192.0.2.66.", bundle)
    assert claim.subject == "process:powershell.exe"
    assert claim.describe() == "powershell.exe connected to 192.0.2.66"
