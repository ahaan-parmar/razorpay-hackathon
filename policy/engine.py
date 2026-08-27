"""Policy engine: (rule fired x severity x confidence) -> one bounded action.

Actions are a fixed, closed set: no_action / flag_for_review /
hold_for_verification / soft_decline. Dry-run by default -- a live
action requires the caller to explicitly pass dry_run=False; nothing in
this codebase ever does that automatically. This is the only module
allowed to produce an action; detection/* only produces evidence and
confidence, and triage/llm_triage.py only explains -- neither can call
this module's decision path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from detection.rules import RuleResult


class Action(str, Enum):
    NO_ACTION = "no_action"
    FLAG_FOR_REVIEW = "flag_for_review"
    HOLD_FOR_VERIFICATION = "hold_for_verification"
    SOFT_DECLINE = "soft_decline"


# Deliberately simple; tuned only on the dev set, never the held-out set.
SOFT_DECLINE_MIN_RULES = 2
SOFT_DECLINE_MIN_CONFIDENCE = 0.8
HOLD_FOR_VERIFICATION_MIN_CONFIDENCE = 0.5


@dataclass
class PolicyDecision:
    action: Action
    dry_run: bool
    fired_rules: list[str]
    confidence: float
    rationale: str


def decide(rule_results: list[RuleResult], confidence: float, dry_run: bool = True) -> PolicyDecision:
    """Map rule/confidence evidence to one bounded action. dry_run=True by default.

    Thresholds (see module-level constants above; deliberately simple,
    tuned only on the dev set, never the held-out set):
    - 0 rules fired -> no_action
    - >=1 rule fired, confidence < HOLD_FOR_VERIFICATION_MIN_CONFIDENCE -> flag_for_review (human looks, nothing blocked)
    - >=1 rule fired, confidence in [HOLD_FOR_VERIFICATION_MIN_CONFIDENCE, SOFT_DECLINE_MIN_CONFIDENCE) -> hold_for_verification (extra step, not a hard block)
    - >=SOFT_DECLINE_MIN_RULES rules fired OR confidence >= SOFT_DECLINE_MIN_CONFIDENCE -> soft_decline (the strongest bounded action available; never a silent hard block)
    """
    fired = [r for r in rule_results if r.fired]
    fired_names = [r.rule_name for r in fired]

    if not fired:
        action = Action.NO_ACTION
        rationale = "no rule fired"
    elif len(fired) >= SOFT_DECLINE_MIN_RULES or confidence >= SOFT_DECLINE_MIN_CONFIDENCE:
        action = Action.SOFT_DECLINE
        rationale = f"{len(fired)} rules fired ({', '.join(fired_names)}), confidence={confidence:.2f}"
    elif confidence >= HOLD_FOR_VERIFICATION_MIN_CONFIDENCE:
        action = Action.HOLD_FOR_VERIFICATION
        rationale = f"1 rule fired ({fired_names[0]}), confidence={confidence:.2f}"
    else:
        action = Action.FLAG_FOR_REVIEW
        rationale = f"1 rule fired ({fired_names[0]}), confidence={confidence:.2f}"

    return PolicyDecision(
        action=action,
        dry_run=dry_run,
        fired_rules=fired_names,
        confidence=confidence,
        rationale=rationale,
    )
