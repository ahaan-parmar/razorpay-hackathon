"""Deterministic, inspectable detection rules -- no black boxes.

Each function takes a window of PaymentAttemptEvent already grouped to
one actor (see detection/baseline.py's group_by_actor) and returns a
RuleResult: whether the rule fired, a coarse severity, and the raw
evidence numbers behind that call. No rule here makes a policy decision
by itself -- that's policy/engine.py's job, using detection/scoring.py's
confidence score alongside these results.

All tunable thresholds live in THRESHOLDS below rather than scattered
across function signatures, so a re-tuning pass (see README's honesty
check and long-window-activity patch, both of which changed exactly one
of these numbers) touches one visible place. Every check_* function
still accepts its thresholds as normal keyword arguments -- THRESHOLDS
only supplies the defaults.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from schema.events import AttemptOutcome, PaymentAttemptEvent


@dataclass(frozen=True)
class RuleThresholds:
    velocity_window_seconds: int = 60
    velocity_threshold: int = 5
    failure_ratio_threshold: float = 0.7
    failure_ratio_min_attempts: int = 5
    bin_sequencing_min_run: int = 4
    device_session_reuse_threshold: int = 5
    timing_regularity_min_attempts: int = 5
    timing_regularity_cv_threshold: float = 0.15
    geo_mismatch_threshold: float = 0.5
    long_window_seconds: int = 4 * 3600
    long_window_count_threshold: int = 10
    long_window_failure_ratio_threshold: float = 0.5
    ip_cluster_window_seconds: int = 4 * 3600
    ip_cluster_min_fingerprints: int = 3
    ip_cluster_failure_ratio_threshold: float = 0.5
    ip_cluster_bin_sequencing_min_run: int = 4


THRESHOLDS = RuleThresholds()


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


def check_velocity(
    events: list[PaymentAttemptEvent],
    window_seconds: int = THRESHOLDS.velocity_window_seconds,
    threshold: int = THRESHOLDS.velocity_threshold,
) -> RuleResult:
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


def check_failure_ratio(
    events: list[PaymentAttemptEvent],
    threshold: float = THRESHOLDS.failure_ratio_threshold,
    min_attempts: int = THRESHOLDS.failure_ratio_min_attempts,
) -> RuleResult:
    """Flag an actor whose decline rate exceeds `threshold` (ignored below `min_attempts` to avoid noise)."""
    if len(events) < min_attempts:
        return RuleResult("failure_ratio", False, "low", {"reason": "insufficient_sample", "n": len(events)})
    failures = sum(1 for e in events if e.outcome != AttemptOutcome.AUTHORIZED)
    ratio = failures / len(events)
    fired = ratio > threshold
    severity = _severity_from_ratio(ratio / threshold) if threshold else "low"
    return RuleResult("failure_ratio", fired, severity, {"failure_ratio": ratio, "n": len(events), "threshold": threshold})


def check_bin_sequencing(
    events: list[PaymentAttemptEvent], min_run: int = THRESHOLDS.bin_sequencing_min_run
) -> RuleResult:
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


def check_device_session_reuse(
    events: list[PaymentAttemptEvent], threshold: int = THRESHOLDS.device_session_reuse_threshold
) -> RuleResult:
    """Flag one device_fingerprint/session_id spanning more than `threshold` distinct account_ids."""
    distinct_accounts = {e.account_id for e in events if e.account_id}
    fired = len(distinct_accounts) > threshold
    severity = _severity_from_ratio(len(distinct_accounts) / threshold) if threshold else "low"
    return RuleResult(
        "device_session_reuse", fired, severity, {"distinct_accounts": len(distinct_accounts), "threshold": threshold}
    )


def check_timing_regularity(
    events: list[PaymentAttemptEvent],
    min_attempts: int = THRESHOLDS.timing_regularity_min_attempts,
    cv_threshold: float = THRESHOLDS.timing_regularity_cv_threshold,
) -> RuleResult:
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


def check_long_window_activity(
    events: list[PaymentAttemptEvent],
    window_seconds: int = THRESHOLDS.long_window_seconds,
    count_threshold: int = THRESHOLDS.long_window_count_threshold,
    failure_ratio_threshold: float = THRESHOLDS.long_window_failure_ratio_threshold,
) -> RuleResult:
    """Flag an actor with more than `count_threshold` attempts AND a failure
    ratio over `failure_ratio_threshold`, both within the same
    `window_seconds` window (default 4 hours).

    Complements check_velocity's 60-second window rather than replacing
    it: this is the signal for a patient, low-and-slow attacker who
    stays under the short-window velocity threshold by spacing attempts
    minutes apart, but still accumulates volume over hours. Requiring
    BOTH count and failure ratio together (not count alone) is what
    keeps this from firing on a legitimately bursty actor (e.g. a
    flash-sale shopper) whose count might cross the threshold but whose
    failure ratio stays low.
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    fired = False
    evidence_count = 0
    evidence_ratio = 0.0
    for i, e in enumerate(sorted_events):
        window_end = e.timestamp + timedelta(seconds=window_seconds)
        window_events = [other for other in sorted_events[i:] if other.timestamp <= window_end]
        count = len(window_events)
        if count == 0:
            continue
        failures = sum(1 for ev in window_events if ev.outcome != AttemptOutcome.AUTHORIZED)
        ratio = failures / count
        if count > count_threshold and ratio > failure_ratio_threshold:
            fired = True
        if count > evidence_count:
            evidence_count, evidence_ratio = count, ratio
    severity = _severity_from_ratio(evidence_count / count_threshold) if fired and count_threshold else "low"
    return RuleResult(
        "long_window_activity",
        fired,
        severity,
        {
            "max_attempts_in_window": evidence_count,
            "failure_ratio_at_max_window": round(evidence_ratio, 4),
            "window_seconds": window_seconds,
            "count_threshold": count_threshold,
            "failure_ratio_threshold": failure_ratio_threshold,
        },
    )


def check_ip_cluster_activity(
    cluster_events: list[PaymentAttemptEvent],
    window_seconds: int = THRESHOLDS.ip_cluster_window_seconds,
    min_fingerprints: int = THRESHOLDS.ip_cluster_min_fingerprints,
    failure_ratio_threshold: float = THRESHOLDS.ip_cluster_failure_ratio_threshold,
    bin_sequencing_min_run: int = THRESHOLDS.ip_cluster_bin_sequencing_min_run,
) -> RuleResult:
    """Flag one IP with more than `min_fingerprints` distinct real device
    fingerprints active inside the same `window_seconds` sliding window
    (default 4 hours), AND (aggregate failure ratio over
    `failure_ratio_threshold` OR a BIN-sequencing run >=
    `bin_sequencing_min_run`) among that window's events.

    NOT part of ALL_RULES / run_all_rules -- unlike every other rule
    here, this one takes `cluster_events` from
    detection/baseline.py's group_by_ip() (all events sharing one IP,
    across every fingerprint), not one actor's own events from
    group_by_actor(). It exists because group_by_actor's
    fingerprint-primary grouping splits an attacker who rotates device
    fingerprints while reusing one IP into several small, individually
    unremarkable actors (see README: 0 of 21 caught on dev, 0 of 15 on
    heldout, before this rule existed). detection/pipeline.py computes
    this once per IP cluster and folds the result into every member
    actor's own rule_results.

    A minimum fingerprint count is deliberately not sufficient signal on
    its own -- a legitimate household or small office sharing one IP
    also has multiple fingerprints. It only fires when that count is
    ALSO paired with elevated failure ratio or BIN sequencing inside the
    same window, which ordinary shared-network use should not produce.

    device_fingerprint=None events (e.g. Razorpay-order-only events
    normalized with no fingerprint, see integrations/normalize.py) are
    excluded from the fingerprint count -- this rule correlates real
    devices, and stays inert where there's no real fingerprint to
    correlate.
    """
    sorted_events = sorted(cluster_events, key=lambda e: e.timestamp)
    fired = False
    evidence_fp_count = 0
    evidence_ratio = 0.0
    evidence_bin_run = 1
    for i, e in enumerate(sorted_events):
        window_end = e.timestamp + timedelta(seconds=window_seconds)
        window_events = [other for other in sorted_events[i:] if other.timestamp <= window_end]
        fingerprints = {ev.device_fingerprint for ev in window_events if ev.device_fingerprint}
        fp_count = len(fingerprints)
        if fp_count <= min_fingerprints:
            continue
        failures = sum(1 for ev in window_events if ev.outcome != AttemptOutcome.AUTHORIZED)
        ratio = failures / len(window_events) if window_events else 0.0
        bin_result = check_bin_sequencing(window_events, min_run=bin_sequencing_min_run)
        bin_run = bin_result.evidence.get("longest_incremental_run", 1)
        if ratio > failure_ratio_threshold or bin_result.fired:
            fired = True
        if fp_count > evidence_fp_count:
            evidence_fp_count, evidence_ratio, evidence_bin_run = fp_count, ratio, bin_run
    severity = _severity_from_ratio(evidence_fp_count / min_fingerprints) if fired and min_fingerprints else "low"
    return RuleResult(
        "ip_cluster_activity",
        fired,
        severity,
        {
            "max_distinct_fingerprints_in_window": evidence_fp_count,
            "failure_ratio_at_max_window": round(evidence_ratio, 4),
            "longest_bin_run_at_max_window": evidence_bin_run,
            "window_seconds": window_seconds,
            "min_fingerprints": min_fingerprints,
            "failure_ratio_threshold": failure_ratio_threshold,
            "bin_sequencing_min_run": bin_sequencing_min_run,
        },
    )


def check_geo_mismatch(
    events: list[PaymentAttemptEvent], threshold: float = THRESHOLDS.geo_mismatch_threshold
) -> RuleResult:
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
    check_long_window_activity,
]
# check_ip_cluster_activity is deliberately not here -- it takes IP-cluster
# events (group_by_ip), not one actor's own events, and is wired in by
# detection/pipeline.py separately, once per IP rather than once per actor.


def run_all_rules(events: list[PaymentAttemptEvent]) -> list[RuleResult]:
    """Run every rule against one actor's event window."""
    return [rule(events) for rule in ALL_RULES]
