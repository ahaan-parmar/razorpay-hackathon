"""Unit tests for detection/rules.py, focused on check_long_window_activity
(the low-and-slow patch), check_ip_cluster_activity (the fingerprint-
rotation patch), and their intended non-interference with legitimate
bursty actors / shared-IP households.
"""

from datetime import datetime, timedelta, timezone

from detection.rules import check_ip_cluster_activity, check_long_window_activity, check_velocity
from schema.events import AttemptOutcome, EventSource, PaymentAttemptEvent


def _event(index: int, offset_seconds: float, outcome: AttemptOutcome, start: datetime) -> PaymentAttemptEvent:
    return PaymentAttemptEvent(
        event_id=f"evt_{index}",
        timestamp=start + timedelta(seconds=offset_seconds),
        ip_address="203.0.113.5",
        session_id="sess_1",
        card_bin="411111",
        amount=10.0,
        outcome=outcome,
        source=EventSource.SYNTHETIC,
    )


def _spaced_events(n: int, spacing_seconds: float, failure_ratio: float) -> list[PaymentAttemptEvent]:
    start = datetime.now(timezone.utc)
    n_failures = round(n * failure_ratio)
    events = []
    for i in range(n):
        outcome = AttemptOutcome.DECLINED if i < n_failures else AttemptOutcome.AUTHORIZED
        events.append(_event(i, i * spacing_seconds, outcome, start))
    return events


def test_fires_when_both_count_and_failure_ratio_exceed_threshold():
    # 20 attempts, 10 min apart (well outside velocity's 60s window),
    # 60% failure -- the low-and-slow shape this rule exists for.
    events = _spaced_events(n=20, spacing_seconds=600, failure_ratio=0.6)
    result = check_long_window_activity(events)
    assert result.fired is True
    assert result.evidence["max_attempts_in_window"] == 20


def test_does_not_fire_on_high_count_low_failure():
    # High volume but a real actor's success rate -- must not fire on
    # count alone, or a legitimate high-frequency user gets caught.
    events = _spaced_events(n=20, spacing_seconds=600, failure_ratio=0.1)
    result = check_long_window_activity(events)
    assert result.fired is False


def test_does_not_fire_on_high_failure_low_count():
    # Bad failure ratio but too few attempts to matter -- must not fire
    # on ratio alone, or a customer whose card keeps failing gets caught.
    events = _spaced_events(n=4, spacing_seconds=600, failure_ratio=1.0)
    result = check_long_window_activity(events)
    assert result.fired is False


def test_does_not_fire_when_events_fall_outside_the_window():
    # Same count/ratio as the firing case, but spread across 20+ hours --
    # outside the default 4-hour window, so no single window ever
    # contains enough of them at once.
    events = _spaced_events(n=20, spacing_seconds=4000, failure_ratio=0.6)
    result = check_long_window_activity(events, window_seconds=4 * 3600)
    assert result.fired is False


def test_velocity_and_long_window_are_independent_signals():
    # A classic sub-60s burst fires velocity (8 attempts, 2s apart --
    # over velocity's threshold=5 but not over long_window's threshold=10,
    # so this isolates velocity specifically).
    burst_events = _spaced_events(n=8, spacing_seconds=2, failure_ratio=0.8)
    assert check_velocity(burst_events).fired is True
    assert check_long_window_activity(burst_events).fired is False

    # A patient attacker fires the long-window rule but not velocity --
    # this is the low-and-slow gap the patch exists to close.
    slow_events = _spaced_events(n=20, spacing_seconds=600, failure_ratio=0.6)
    assert check_velocity(slow_events).fired is False
    assert check_long_window_activity(slow_events).fired is True


def test_empty_events_does_not_crash():
    result = check_long_window_activity([])
    assert result.fired is False
    assert result.evidence["max_attempts_in_window"] == 0


def _cluster_event(
    index: int,
    fingerprint: str | None,
    offset_seconds: float,
    outcome: AttemptOutcome,
    start: datetime,
    card_bin: str = "411111",
    ip: str = "203.0.113.5",
) -> PaymentAttemptEvent:
    return PaymentAttemptEvent(
        event_id=f"evt_{index}",
        timestamp=start + timedelta(seconds=offset_seconds),
        ip_address=ip,
        device_fingerprint=fingerprint,
        session_id=f"sess_{index}",
        card_bin=card_bin,
        amount=10.0,
        outcome=outcome,
        source=EventSource.SYNTHETIC,
    )


def test_ip_cluster_fires_on_enough_fingerprints_with_high_failure_in_window():
    # 5 distinct fingerprints, one event each, all within an hour, 4/5 declined --
    # over both the >3 fingerprint gate and the 0.5 failure-ratio threshold.
    start = datetime.now(timezone.utc)
    outcomes = [AttemptOutcome.DECLINED] * 4 + [AttemptOutcome.AUTHORIZED]
    events = [
        _cluster_event(i, f"fp_{i}", i * 600, outcomes[i], start, card_bin=f"{400000 + i * 137:06d}")
        for i in range(5)
    ]
    result = check_ip_cluster_activity(events)
    assert result.fired is True
    assert result.evidence["max_distinct_fingerprints_in_window"] == 5


def test_ip_cluster_does_not_fire_on_fingerprint_count_alone():
    # Same 5-fingerprint shape, but everyone succeeds and cards are unrelated --
    # the household shape. Count alone must not be sufficient.
    start = datetime.now(timezone.utc)
    events = [
        _cluster_event(i, f"fp_{i}", i * 600, AttemptOutcome.AUTHORIZED, start, card_bin=f"{400000 + i * 9137:06d}")
        for i in range(5)
    ]
    result = check_ip_cluster_activity(events)
    assert result.fired is False


def test_ip_cluster_does_not_fire_below_min_fingerprint_count():
    # Only 3 distinct fingerprints (threshold is >3, i.e. needs 4+), even
    # with a high failure ratio -- the count gate must hold on its own.
    start = datetime.now(timezone.utc)
    events = [
        _cluster_event(i, f"fp_{i}", i * 600, AttemptOutcome.DECLINED, start, card_bin=f"{400000 + i * 137:06d}")
        for i in range(3)
    ]
    result = check_ip_cluster_activity(events)
    assert result.fired is False


def test_ip_cluster_fires_via_bin_sequencing_even_with_low_failure():
    # 5 fingerprints, mostly successful (low failure ratio), but the cards
    # used form an incremental run -- the OR path, not the failure-ratio path.
    start = datetime.now(timezone.utc)
    events = [
        _cluster_event(i, f"fp_{i}", i * 600, AttemptOutcome.AUTHORIZED, start, card_bin=f"{400000 + i:06d}")
        for i in range(5)
    ]
    result = check_ip_cluster_activity(events)
    assert result.fired is True
    assert result.evidence["failure_ratio_at_max_window"] == 0.0


def test_ip_cluster_true_sliding_window_not_fixed_buckets():
    # Events start at an arbitrary, unaligned offset (not 0:00, not any
    # "clean" boundary) and span under 4 hours -- a fixed-bucket
    # implementation keyed to clock-aligned windows could split this
    # across two buckets and undercount each. A true sliding window (every
    # event is a candidate window start) must still catch it regardless of
    # where the campaign happens to fall on the clock.
    start = datetime.now(timezone.utc) + timedelta(minutes=37, seconds=13)
    offsets_minutes = [0, 55, 118, 172, 210]  # spans 3.5 hours, awkward spacing
    events = [
        _cluster_event(i, f"fp_{i}", offsets_minutes[i] * 60, AttemptOutcome.DECLINED, start, card_bin=f"{400000 + i * 137:06d}")
        for i in range(5)
    ]
    result = check_ip_cluster_activity(events)
    assert result.fired is True


def test_ip_cluster_household_hard_negative_does_not_fire():
    # Mirrors data/generate_synthetic.py's inject_shared_ip_household shape
    # at unit-test scale: 4 distinct fingerprints, spread across days (not
    # hours), a couple of attempts each, high success, distinct cards.
    start = datetime.now(timezone.utc)
    events = []
    idx = 0
    for member in range(4):
        member_offset_hours = member * 30  # days apart, not hours
        for attempt in range(2):
            outcome = AttemptOutcome.AUTHORIZED if attempt == 1 else AttemptOutcome.DECLINED
            events.append(
                _cluster_event(
                    idx,
                    f"fp_{member}",
                    member_offset_hours * 3600 + attempt * 3600,
                    outcome,
                    start,
                    card_bin=f"{400000 + member * 51241:06d}",
                )
            )
            idx += 1
    result = check_ip_cluster_activity(events)
    assert result.fired is False


def test_ip_cluster_excludes_null_fingerprints_from_count():
    # None fingerprints (e.g. Razorpay-order-only events) must not count
    # toward the distinct-fingerprint tally.
    start = datetime.now(timezone.utc)
    events = [_cluster_event(i, None, i * 60, AttemptOutcome.DECLINED, start) for i in range(6)]
    result = check_ip_cluster_activity(events)
    assert result.fired is False
    assert result.evidence["max_distinct_fingerprints_in_window"] == 0


def test_ip_cluster_empty_events_does_not_crash():
    result = check_ip_cluster_activity([])
    assert result.fired is False
    assert result.evidence["max_distinct_fingerprints_in_window"] == 0
