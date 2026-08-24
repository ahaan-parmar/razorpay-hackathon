"""Population-level baseline computation.

A brand-new bot actor has no self-history to compare against -- that's
the whole reason it looks anomalous. So the "control" every actor's
window gets scored against here is the population norm (median attempts
per actor, median failure ratio, median timing regularity) computed over
a reference batch, not that actor's own past behavior.

Grouping is by device_fingerprint when present, falling back to
ip_address -- a deliberate MVP simplification (documented as a scope
limitation in the README) rather than the full multi-key grouping
(IP + device + session + BIN) the problem definition lists; card-testing
bots typically hold one device/session fixed while rotating cards, so
this axis catches the injected attack patterns while staying within
10-day scope.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from schema.events import AttemptOutcome, PaymentAttemptEvent


@dataclass
class PopulationBaseline:
    median_attempts_per_actor: float
    median_failure_ratio: float
    median_timing_cv: float


def actor_key(event: PaymentAttemptEvent) -> str:
    return event.device_fingerprint or event.ip_address


def group_by_actor(events: list[PaymentAttemptEvent]) -> dict[str, list[PaymentAttemptEvent]]:
    groups: dict[str, list[PaymentAttemptEvent]] = {}
    for e in events:
        groups.setdefault(actor_key(e), []).append(e)
    return groups


def failure_ratio(events: list[PaymentAttemptEvent]) -> float:
    if not events:
        return 0.0
    return sum(1 for e in events if e.outcome != AttemptOutcome.AUTHORIZED) / len(events)


def timing_cv(events: list[PaymentAttemptEvent]) -> float:
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    if len(sorted_events) < 2:
        return 0.0
    deltas = [
        (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
        for i in range(1, len(sorted_events))
    ]
    mean = statistics.mean(deltas)
    return statistics.pstdev(deltas) / mean if mean else 0.0


def compute_population_baseline(reference_events: list[PaymentAttemptEvent]) -> PopulationBaseline:
    """Compute population-level reference stats from a reference window."""
    groups = group_by_actor(reference_events)
    attempts = [len(g) for g in groups.values()]
    failure_ratios = [failure_ratio(g) for g in groups.values() if len(g) >= 2]
    cvs = [timing_cv(g) for g in groups.values() if len(g) >= 3]
    return PopulationBaseline(
        median_attempts_per_actor=statistics.median(attempts) if attempts else 1.0,
        median_failure_ratio=statistics.median(failure_ratios) if failure_ratios else 0.1,
        median_timing_cv=statistics.median(cvs) if cvs else 0.5,
    )


def compute_actor_baseline(events: list[PaymentAttemptEvent], actor_key_value: str) -> PopulationBaseline:
    """Compute the reference stats one actor's window is scored against.

    `events` is the reference/control population (e.g. this evaluation
    batch's full traffic), not just this actor's own events -- see the
    module docstring for why. `actor_key_value` is accepted for interface
    symmetry with detection/scoring.py and isn't used to filter.
    """
    return compute_population_baseline(events)
