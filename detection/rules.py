"""Deterministic, inspectable detection rules -- no black boxes.

Each function takes a window of PaymentAttemptEvent already grouped to
one actor (see detection/baseline.py's group_by_actor) and returns a
RuleResult: whether the rule fired, a coarse severity, and the raw
evidence numbers behind that call. No rule here makes a policy decision
by itself -- that's policy/engine.py's job, using detection/scoring.py's
confidence score alongside these results.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from schema.events import AttemptOutcome, PaymentAttemptEvent


@dataclass
class RuleResult:
    rule_name: str
    fired: bool
    severity: str  # "low" | "medium" | "high"
    evidence: dict[str, Any] = field(default_factory=dict)


def _severity_from_ratio(ratio: float) -> str:
    if ratio >= 2.0:
        return "high"
    if ratio >= 1.2:
        return "medium"
    return "low"


def check_velocity(events: list[PaymentAttemptEvent], window_seconds: int = 60, threshold: int = 5) -> RuleResult:
    """Flag an actor with more than `threshold` attempts inside any `window_seconds` window."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    max_count = 0
    for i, e in enumerate(sorted_events):
        window_end = e.timestamp + timedelta(seconds=window_seconds)
        count = sum(1 for other in sorted_events[i:] if other.timestamp <= window_end)
        max_count = max(max_count, count)
    fired = max_count > threshold
    severity = _severity_from_ratio(max_count / threshold) if threshold else "low"
    return RuleResult(
        "velocity",
        fired,
        severity,
        {"max_attempts_in_window": max_count, "window_seconds": window_seconds, "threshold": threshold},
    )


def check_failure_ratio(events: list[PaymentAttemptEvent], threshold: float = 0.7, min_attempts: int = 5) -> RuleResult:
    """Flag an actor whose decline rate exceeds `threshold` (ignored below `min_attempts` to avoid noise)."""
    if len(events) < min_attempts:
        return RuleResult("failure_ratio", False, "low", {"reason": "insufficient_sample", "n": len(events)})
    failures = sum(1 for e in events if e.outcome != AttemptOutcome.AUTHORIZED)
    ratio = failures / len(events)
    fired = ratio > threshold
    severity = _severity_from_ratio(ratio / threshold) if threshold else "low"
    return RuleResult("failure_ratio", fired, severity, {"failure_ratio": ratio, "n": len(events), "threshold": threshold})


def check_bin_sequencing(events: list[PaymentAttemptEvent], min_run: int = 4) -> RuleResult:
    """Flag a run of card_bin values that are incremental by 1, length >= min_run."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    bins = [int(e.card_bin) for e in sorted_events]
    best_run, current_run = 1, 1
    for i in range(1, len(bins)):
        if bins[i] - bins[i - 1] == 1:
            current_run += 1
            best_run = max(best_run, current_run)
        else:
            current_run = 1
    fired = best_run >= min_run
    severity = _severity_from_ratio(best_run / min_run) if min_run else "low"
    return RuleResult("bin_sequencing", fired, severity, {"longest_incremental_run": best_run, "min_run": min_run})


def check_device_session_reuse(events: list[PaymentAttemptEvent], threshold: int = 5) -> RuleResult:
    """Flag one device_fingerprint/session_id spanning more than `threshold` distinct account_ids."""
    distinct_accounts = {e.account_id for e in events if e.account_id}
    fired = len(distinct_accounts) > threshold
    severity = _severity_from_ratio(len(distinct_accounts) / threshold) if threshold else "low"
    return RuleResult(
        "device_session_reuse", fired, severity, {"distinct_accounts": len(distinct_accounts), "threshold": threshold}
    )


def check_timing_regularity(events: list[PaymentAttemptEvent], min_attempts: int = 5, cv_threshold: float = 0.15) -> RuleResult:
    """Flag inter-attempt timing too regular to be human: coefficient of variation below cv_threshold."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    if len(sorted_events) < min_attempts:
        return RuleResult("timing_regularity", False, "low", {"reason": "insufficient_sample", "n": len(sorted_events)})
    deltas = [
        (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
        for i in range(1, len(sorted_events))
    ]
    mean = statistics.mean(deltas)
    cv = statistics.pstdev(deltas) / mean if mean else 0.0
    fired = cv < cv_threshold
    severity = _severity_from_ratio((cv_threshold - cv) / cv_threshold) if cv_threshold else "low"
    return RuleResult(
        "timing_regularity", fired, severity, {"coefficient_of_variation": cv, "cv_threshold": cv_threshold, "n": len(sorted_events)}
    )


def check_geo_mismatch(events: list[PaymentAttemptEvent], threshold: float = 0.5) -> RuleResult:
    """Flag ip_country diverging from account_country on more than `threshold` of events with both known."""
    known = [e for e in events if e.ip_country and e.account_country]
    if not known:
        return RuleResult("geo_mismatch", False, "low", {"reason": "no_geo_data"})
    mismatches = sum(1 for e in known if e.ip_country != e.account_country)
    ratio = mismatches / len(known)
    fired = ratio > threshold
    severity = _severity_from_ratio(ratio / threshold) if threshold else "low"
    return RuleResult("geo_mismatch", fired, severity, {"mismatch_ratio": ratio, "n": len(known), "threshold": threshold})


ALL_RULES = [
    check_velocity,
    check_failure_ratio,
    check_bin_sequencing,
    check_device_session_reuse,
    check_timing_regularity,
    check_geo_mismatch,
]


def run_all_rules(events: list[PaymentAttemptEvent]) -> list[RuleResult]:
    """Run every rule against one actor's event window."""
    return [rule(events) for rule in ALL_RULES]
