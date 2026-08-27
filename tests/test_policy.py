"""Unit tests for policy/engine.py's action-boundary thresholds."""

from detection.rules import RuleResult
from policy.engine import Action, decide


def _rule(name: str, fired: bool) -> RuleResult:
    return RuleResult(name, fired, "low", {})


def test_no_rules_fired_is_no_action_regardless_of_confidence():
    # A high confidence score with zero corroborating rules must never
    # act -- this is the exact property the hard-negative eval cases rely on.
    decision = decide([_rule("velocity", False)], confidence=0.99)
    assert decision.action == Action.NO_ACTION


def test_one_rule_low_confidence_is_flag_for_review():
    decision = decide([_rule("velocity", True)], confidence=0.3)
    assert decision.action == Action.FLAG_FOR_REVIEW


def test_one_rule_mid_confidence_is_hold_for_verification():
    decision = decide([_rule("velocity", True)], confidence=0.6)
    assert decision.action == Action.HOLD_FOR_VERIFICATION


def test_two_rules_is_soft_decline_even_at_low_confidence():
    decision = decide([_rule("velocity", True), _rule("failure_ratio", True)], confidence=0.1)
    assert decision.action == Action.SOFT_DECLINE


def test_one_rule_high_confidence_is_soft_decline():
    decision = decide([_rule("velocity", True)], confidence=0.85)
    assert decision.action == Action.SOFT_DECLINE


def test_dry_run_flag_is_recorded_not_acted_on():
    decision = decide([_rule("velocity", True)], confidence=0.9, dry_run=False)
    assert decision.dry_run is False
    assert decision.action == Action.SOFT_DECLINE  # same decision either way -- dry_run never changes the action
