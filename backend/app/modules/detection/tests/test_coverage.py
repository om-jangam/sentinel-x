"""What the rule set looks for, as a Navigator layer — and what the layer must not imply."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.attack_navigator import LAYER_VERSION, MAX_COMMENT
from app.modules.detection.domain.coverage import coverage, coverage_layer
from app.modules.detection.domain.predicates import AllOf
from app.modules.detection.domain.rules import Attack, RuleMeta, RuleType, SingleEventRule, attack_from_tags
from app.modules.detection.infrastructure.rule_loader import load_rules

GENERATED = datetime(2026, 10, 11, tzinfo=UTC)


def rule(title: str, *techniques: str, path: str = "sigma/x.yml", tactics: tuple[str, ...] = ()) -> SingleEventRule:
    return SingleEventRule(
        meta=RuleMeta(
            id=f"id-{title}",
            title=title,
            description="d",
            level="high",
            severity_id=4,
            attack=Attack(techniques=techniques, tactics=tactics),
            version="v",
            path=path,
        ),
        logsource="process_creation",
        predicate=AllOf(()),  # coverage reads metadata; it never evaluates the rule
        type=RuleType.SIGMA,
    )


def test_a_technique_is_scored_by_the_rules_that_name_it_only() -> None:
    """A rule tagged T1059.001 does not score T1059: Navigator shows sub-techniques under the parent, and
    inventing a parent score would overstate the row an analyst reads first."""
    counted = coverage([rule("child", "T1059.001"), rule("parent", "T1059"), rule("both", "T1059", "T1059.001")])
    scores = {technique.technique_id: technique.rules for technique in counted.techniques}
    assert scores == {"T1059": 2, "T1059.001": 2}


def test_own_and_community_rules_are_counted_apart() -> None:
    counted = coverage(
        [
            rule("ours", "T1110.003", path="threshold/spray.yml"),
            rule("theirs", "T1110.003", path="sigmahq/windows/x.yml"),
            rule("theirs too", "T1110.003", path="sigmahq/windows/y.yml"),
        ]
    )
    spray = counted.techniques[0]
    assert (spray.rules, spray.own, spray.community) == (3, 1, 2)


def test_rules_that_name_no_technique_are_counted_not_hidden() -> None:
    counted = coverage([rule("tagged", "T1059"), rule("untagged"), rule("also untagged")])
    assert counted.untagged_rules == 2
    assert counted.technique_count == 1
    assert counted.rule_count == 3


def test_tactics_are_ordered_by_how_many_rules_name_them() -> None:
    counted = coverage(
        [
            rule("a", "T1059", tactics=("execution",)),
            rule("b", "T1059", tactics=("execution",)),
            rule("c", "T1003", tactics=("credential_access",)),
        ]
    )
    assert counted.tactics == (("execution", 2), ("credential_access", 1))


def test_the_layer_says_what_a_score_is_and_is_not() -> None:
    layer = coverage_layer([rule("a", "T1059.001")], generated=GENERATED)
    assert layer["versions"]["layer"] == LAYER_VERSION
    assert layer["domain"] == "enterprise-attack"
    # The claim the format invites — "we cover this" — is the one thing the description has to deny.
    assert "not evidence that it would be caught" in layer["description"]
    assert "docs/evaluation" in layer["description"]
    assert layer["legendItems"][0]["label"] == "Rules look for this technique"


def test_each_entry_carries_its_score_its_rules_and_whether_it_is_a_sub_technique() -> None:
    layer = coverage_layer([rule("Encoded PowerShell", "T1059.001"), rule("Spray", "T1110")], generated=GENERATED)
    entries = {entry["techniqueID"]: entry for entry in layer["techniques"]}
    assert [entry["techniqueID"] for entry in layer["techniques"]] == ["T1059.001", "T1110"], "sorted by id"
    assert entries["T1059.001"]["showSubtechniques"] is True
    assert entries["T1110"]["showSubtechniques"] is False
    assert entries["T1059.001"]["comment"] == "Encoded PowerShell"
    assert {item["name"]: item["value"] for item in entries["T1059.001"]["metadata"]} == {
        "rules": "1",
        "Sentinel-X rules": "1",
        "community rules": "0",
    }


def test_the_gradient_tops_out_at_the_busiest_technique() -> None:
    rules = [rule(f"r{i}", "T1059.001") for i in range(7)] + [rule("one", "T1110")]
    layer = coverage_layer(rules, generated=GENERATED)
    assert layer["gradient"]["maxValue"] == 7


def test_a_comment_is_capped_and_lists_a_few_rules_not_all_of_them() -> None:
    layer = coverage_layer([rule(f"rule number {i:03d} " + "x" * 80, "T1059") for i in range(40)], generated=GENERATED)
    comment = layer["techniques"][0]["comment"]
    assert len(comment) <= MAX_COMMENT
    assert layer["techniques"][0]["score"] == 40, "the score still counts every rule"


def test_an_empty_rule_set_is_an_empty_layer_not_a_broken_one() -> None:
    layer = coverage_layer([], generated=GENERATED)
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1, "Navigator needs a usable scale"
    assert "0 loaded detection rules" in layer["description"]


# --------------------------------------------------------------- the shipped set
def test_the_shipped_rules_cover_what_the_evaluation_measured() -> None:
    counted = coverage(load_rules().all())
    assert counted.technique_count > 150
    covered = {technique.technique_id for technique in counted.techniques}
    # Every technique a Sentinel-X rule claims, and the priority ones the evaluation detected.
    assert {"T1110.003", "T1059.001", "T1069.002", "T1033", "T1027", "T1105"} <= covered
    assert counted.untagged_rules == 93, "community rules with no ATT&CK tag, counted rather than ignored"


def test_attack_v17_tactic_names_are_read_and_the_old_name_still_means_the_same_tactic() -> None:
    """ATT&CK v17 renamed TA0005 Defense Evasion to Stealth and added TA0112 Defense Impairment.

    The shipped pack uses the new names on 413 tags, every one of which was dropped before they were
    added, so `stealth` — the largest tactic in the set — reported as no tactic at all.
    """
    assert attack_from_tags(["attack.stealth"]).tactics == ("stealth",)
    assert attack_from_tags(["attack.defense-impairment"]).tactics == ("defense_impairment",)
    assert attack_from_tags(["attack.defense_evasion"]).tactics == ("stealth",), "renamed, not removed"
    assert attack_from_tags(["attack.s0002", "attack.g0069"]).tactics == (), "software and groups are not tactics"

    tactics = dict(coverage(load_rules().all()).tactics)
    assert tactics["stealth"] > tactics["execution"], "the busiest tactic in the shipped set"
    assert tactics["defense_impairment"] > 0
