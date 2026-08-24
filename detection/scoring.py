"""Confidence/differential scoring layer.

Scores how far an actor's window deviates from the population baseline
(signal-vs-control ratio) on three axes -- attempt volume, failure
ratio, timing regularity -- and combines them into one 0-1 confidence
score, rather than a bare rule-fired boolean. This is the layer that
separates confirmed abuse from noise before policy/engine.py decides an
action.
"""

from __future__ import annotations

from detection.baseline import PopulationBaseline, failure_ratio, timing_cv
from schema.events import PaymentAttemptEvent

_SATURATION_RATIO = 4.0


def score_deviation(events: list[PaymentAttemptEvent], baseline: PopulationBaseline) -> float:
    """Return a 0-1 confidence score for how anomalous this window is vs baseline.

    A ratio of 1.0 on an axis means "exactly at the population median";
    each axis saturates at _SATURATION_RATIO (4x the population norm).
    """
    n = len(events)
    volume_ratio = n / baseline.median_attempts_per_actor if baseline.median_attempts_per_actor else float(n)

    ratio = failure_ratio(events) if n >= 2 else 0.0
    failure_deviation = ratio / baseline.median_failure_ratio if baseline.median_failure_ratio else ratio

    cv = timing_cv(events) if n >= 3 else baseline.median_timing_cv
    # low CV (too regular) is the anomaly signal here, so invert it
    timing_deviation = (baseline.median_timing_cv / cv) if cv > 0 else _SATURATION_RATIO

    axes = [volume_ratio, failure_deviation, timing_deviation]
    combined = sum(min(a, _SATURATION_RATIO) for a in axes) / (_SATURATION_RATIO * len(axes))
    return max(0.0, min(1.0, combined))
