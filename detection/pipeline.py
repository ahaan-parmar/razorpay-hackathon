"""Orchestrates one full pass: group events by actor -> run rules -> score -> decide.

Added beyond the original milestone-1 file list because both
cli/main.py (live/demo entrypoint) and eval/run_eval.py (held-out eval
entrypoint) need the exact same grouping -> rules -> scoring -> policy
wiring. Putting it here once avoids the two entrypoints silently
drifting out of sync with each other -- the same kind of implicit-drift
risk integrations/normalize.py exists to prevent for schema conversion.

Also where the second, IP-level grouping dimension gets folded in:
check_ip_cluster_activity runs once per IP (not once per actor) against
detection/baseline.py's group_by_ip(), and its RuleResult -- if fired --
is appended to every fingerprint-actor sharing that IP's own
rule_results before policy/engine.py's decide() runs. That's the whole
mechanism; policy/engine.py itself needed no changes, since a shared IP
cluster verdict is just one more entry in the same rule_results list
the other 7 rules populate, still subject to the existing >=2-rules-or-
confidence>=0.8 bar before any soft_decline.
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.baseline import actor_key, compute_actor_baseline, group_by_actor, group_by_ip
from detection.rules import RuleResult, check_ip_cluster_activity, run_all_rules
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
    actor_events: list[PaymentAttemptEvent],
    reference_events: list[PaymentAttemptEvent],
    dry_run: bool = True,
    ip_cluster_results: dict[str, RuleResult] | None = None,
) -> ActorEvaluation:
    """Run every rule on one actor's events, score confidence against the
    population baseline, and decide a policy action.

    `reference_events` is the population the baseline is computed from
    (typically the full batch this actor's events were drawn from) --
    see detection/baseline.py for why this isn't the actor's own history.

    `ip_cluster_results` is an optional {ip_address: RuleResult} map,
    precomputed once per batch by evaluate_batch (see module docstring).
    If this actor's IP has a fired cluster result, it's appended to
    their own rule_results. Optional and defaults to None so direct
    callers (tests, one-off scripts) work unchanged without it.
    """
    if not actor_events:
        raise ValueError("actor_events must be non-empty -- evaluate_batch never calls this with an empty group")
    baseline = compute_actor_baseline(reference_events, actor_key(actor_events[0]))
    rule_results = run_all_rules(actor_events)

    if ip_cluster_results is not None:
        cluster_result = ip_cluster_results.get(actor_events[0].ip_address)
        if cluster_result is not None and cluster_result.fired:
            rule_results = rule_results + [cluster_result]

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

    Also computes the IP-cluster view of the same batch once (see
    module docstring) and folds each actor's cluster verdict into their
    own evaluation.
    """
    groups = group_by_actor(events)
    ip_clusters = group_by_ip(events)
    ip_cluster_results = {ip: check_ip_cluster_activity(cluster_events) for ip, cluster_events in ip_clusters.items()}
    return [
        evaluate_actor(actor_events, events, dry_run=dry_run, ip_cluster_results=ip_cluster_results)
        for actor_events in groups.values()
    ]
