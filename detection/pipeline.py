"""Orchestrates one full pass: group events by actor -> run rules -> score -> decide.

Added beyond the original milestone-1 file list because both
cli/main.py (live/demo entrypoint) and eval/run_eval.py (held-out eval
entrypoint) need the exact same grouping -> rules -> scoring -> policy
wiring. Putting it here once avoids the two entrypoints silently
drifting out of sync with each other -- the same kind of implicit-drift
risk integrations/normalize.py exists to prevent for schema conversion.
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.baseline import actor_key, compute_actor_baseline, group_by_actor
from detection.rules import RuleResult, run_all_rules
from detection.scoring import score_deviation
from policy.engine import PolicyDecision, decide
from schema.events import PaymentAttemptEvent


@dataclass
class ActorEvaluation:
    actor: str
    events: list[PaymentAttemptEvent]
    rule_results: list[RuleResult]
    confidence: float
    decision: PolicyDecision


def evaluate_actor(
    actor_events: list[PaymentAttemptEvent], reference_events: list[PaymentAttemptEvent], dry_run: bool = True
) -> ActorEvaluation:
    """Run every rule on one actor's events, score confidence against the
    population baseline, and decide a policy action.

    `reference_events` is the population the baseline is computed from
    (typically the full batch this actor's events were drawn from) --
    see detection/baseline.py for why this isn't the actor's own history.
    """
    baseline = compute_actor_baseline(reference_events, actor_key(actor_events[0]))
    rule_results = run_all_rules(actor_events)
    confidence = score_deviation(actor_events, baseline)
    decision = decide(rule_results, confidence, dry_run=dry_run)
    return ActorEvaluation(
        actor=actor_key(actor_events[0]),
        events=actor_events,
        rule_results=rule_results,
        confidence=confidence,
        decision=decision,
    )


def evaluate_batch(events: list[PaymentAttemptEvent], dry_run: bool = True) -> list[ActorEvaluation]:
    """Group a batch of events by actor and evaluate each actor independently,
    all scored against the same batch-level population baseline.
    """
    groups = group_by_actor(events)
    return [evaluate_actor(actor_events, events, dry_run=dry_run) for actor_events in groups.values()]
