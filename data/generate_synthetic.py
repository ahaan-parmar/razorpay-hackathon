"""Synthetic event generator with injected attack sequences and labels.

Emits PaymentAttemptEvent objects directly (source=EventSource.SYNTHETIC)
-- it is schema-native by construction, so it needs no separate
normalization step (contrast with integrations/normalize.py, which
exists because Razorpay's raw API responses are NOT already in this
shape).

build_dataset(seed=...) assembles one full labeled dataset: baseline
traffic plus several independent injected attack sequences, shuffled.
__main__ generates two independent datasets from two different seeds --
dev.jsonl (used for rule/threshold tuning) and heldout.jsonl (frozen,
never touched again) -- per CLAUDE.md's constraint that precision/
recall/FP-rate must come from a held-out set never used for tuning.
"""

from __future__ import annotations

import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

from schema.events import AttackType, AttemptOutcome, EventSource, PaymentAttemptEvent

_COUNTRIES = ["IN", "US", "GB", "AE", "SG", "DE"]
_BASELINE_DECLINE_REASONS = ["insufficient_funds", "issuer_declined", "expired_card"]
_ATTACK_DECLINE_REASONS = ["card_declined", "invalid_cvv", "invalid_expiry"]
# Small pool of well-known demo/test BIN prefixes, used only as synthetic
# labels here -- not asserted to be real Razorpay test cards. That
# verification happens separately in integrations/razorpay_client.py.
_TEST_BIN_POOL = ["400000", "411111", "424242", "451234", "510000", "555555", "378282", "601111"]


def _rand_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _rand_hex(n: int = 16) -> str:
    return uuid.uuid4().hex[:n]


def _event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def generate_baseline_traffic(
    n: int, start: datetime | None = None, days: int = 14
) -> list[PaymentAttemptEvent]:
    """Generate n plausible legitimate checkout events, labeled is_abuse=False.

    Timestamps are spread uniformly across `days` (human-jittered, no
    tight clustering); actors, cards, and outcomes vary freely; decline
    rate is a normal ~8%.
    """
    start = start or (datetime.now(timezone.utc) - timedelta(days=days))
    events = []
    for _ in range(n):
        ts = start + timedelta(seconds=random.uniform(0, days * 86400))
        country = random.choice(_COUNTRIES)
        outcome = random.choices(
            [AttemptOutcome.AUTHORIZED, AttemptOutcome.DECLINED], weights=[0.92, 0.08]
        )[0]
        events.append(
            PaymentAttemptEvent(
                event_id=_event_id(),
                timestamp=ts,
                ip_address=_rand_ip(),
                device_fingerprint=_rand_hex(20),
                session_id=_rand_hex(24),
                account_id=f"acct_{_rand_hex(10)}",
                card_bin=random.choice(_TEST_BIN_POOL),
                card_last4=f"{random.randint(0, 9999):04d}",
                card_network=random.choice(["visa", "mastercard", "amex"]),
                amount=round(random.uniform(150, 8000), 2),
                currency="INR",
                outcome=outcome,
                decline_reason=(
                    None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_BASELINE_DECLINE_REASONS)
                ),
                ip_country=country,
                account_country=country,
                source=EventSource.SYNTHETIC,
                is_abuse=False,
                attack_type=AttackType.NONE,
            )
        )
    return events


def inject_card_testing_velocity(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks rapid low-value auth attempts from one actor, labeled
    CARD_TESTING_VELOCITY. Returns events + the injected sequence (combined list).

    One IP/device/session, sub-few-second spacing, low amounts (typical
    card-testing $1-style probes), high decline rate.
    """
    ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
    start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
    attack = []
    for i in range(n_attacks):
        ts = start + timedelta(seconds=i * random.uniform(0.5, 3.0))
        outcome = random.choices(
            [AttemptOutcome.DECLINED, AttemptOutcome.AUTHORIZED], weights=[0.9, 0.1]
        )[0]
        attack.append(
            PaymentAttemptEvent(
                event_id=_event_id(),
                timestamp=ts,
                ip_address=ip,
                device_fingerprint=device,
                session_id=session,
                account_id=None,
                card_bin=random.choice(_TEST_BIN_POOL),
                card_last4=f"{random.randint(0, 9999):04d}",
                card_network=random.choice(["visa", "mastercard"]),
                amount=round(random.uniform(1, 50), 2),
                currency="INR",
                outcome=outcome,
                decline_reason=(
                    None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_ATTACK_DECLINE_REASONS)
                ),
                ip_country=random.choice(_COUNTRIES),
                account_country=None,
                source=EventSource.SYNTHETIC,
                is_abuse=True,
                attack_type=AttackType.CARD_TESTING_VELOCITY,
            )
        )
    return events + attack


def inject_bin_sequencing(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks with incremental/patterned card BINs, labeled
    BIN_SEQUENCING. Returns events + the injected sequence (combined list).
    """
    ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
    start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
    base_bin = random.randint(400000, 599999)
    attack = []
    for i in range(n_attacks):
        ts = start + timedelta(seconds=i * random.uniform(1.0, 5.0))
        outcome = random.choices(
            [AttemptOutcome.DECLINED, AttemptOutcome.AUTHORIZED], weights=[0.85, 0.15]
        )[0]
        attack.append(
            PaymentAttemptEvent(
                event_id=_event_id(),
                timestamp=ts,
                ip_address=ip,
                device_fingerprint=device,
                session_id=session,
                account_id=None,
                card_bin=f"{base_bin + i:06d}",
                card_last4=f"{random.randint(0, 9999):04d}",
                card_network="visa",
                amount=round(random.uniform(1, 100), 2),
                currency="INR",
                outcome=outcome,
                decline_reason=(
                    None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_ATTACK_DECLINE_REASONS)
                ),
                ip_country=random.choice(_COUNTRIES),
                account_country=None,
                source=EventSource.SYNTHETIC,
                is_abuse=True,
                attack_type=AttackType.BIN_SEQUENCING,
            )
        )
    return events + attack


def inject_credential_stuffing(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks reusing one device/session across many account_ids,
    labeled CREDENTIAL_STUFFING. Returns events + the injected sequence
    (combined list).
    """
    device, session, ip = _rand_hex(20), _rand_hex(24), _rand_ip()
    start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
    attack = []
    for i in range(n_attacks):
        ts = start + timedelta(seconds=i * random.uniform(0.5, 4.0))
        outcome = random.choices(
            [AttemptOutcome.FAILED, AttemptOutcome.AUTHORIZED], weights=[0.88, 0.12]
        )[0]
        attack.append(
            PaymentAttemptEvent(
                event_id=_event_id(),
                timestamp=ts,
                ip_address=ip,
                device_fingerprint=device,
                session_id=session,
                account_id=f"acct_{_rand_hex(10)}",
                card_bin=random.choice(_TEST_BIN_POOL),
                card_last4=f"{random.randint(0, 9999):04d}",
                card_network=random.choice(["visa", "mastercard"]),
                amount=round(random.uniform(100, 3000), 2),
                currency="INR",
                outcome=outcome,
                decline_reason=None if outcome == AttemptOutcome.AUTHORIZED else "authentication_failed",
                ip_country=random.choice(_COUNTRIES),
                account_country=random.choice(_COUNTRIES),
                source=EventSource.SYNTHETIC,
                is_abuse=True,
                attack_type=AttackType.CREDENTIAL_STUFFING,
            )
        )
    return events + attack


def inject_legit_retry_burst(
    events: list[PaymentAttemptEvent], n_cases: int
) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a genuinely legitimate but bursty pattern: a real
    returning customer fails 2-3 attempts (bad CVV/expiry typo) then
    succeeds on the same card, seconds-to-tens-of-seconds apart. Labeled
    is_abuse=False, attack_type=NONE.

    This is the deliberately ambiguous case the milestone 6-7 honesty
    check and the milestone 9 graceful-failure writeup are built around:
    it looks bot-adjacent on failure_ratio and volume (a real user
    retrying looks similar to a bot retrying), but it is not abuse, and a
    detector this blunt must not silently hard-block it.
    """
    attack = []
    for _ in range(n_cases):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        account = f"acct_{_rand_hex(10)}"
        card_bin = random.choice(_TEST_BIN_POOL)
        card_last4 = f"{random.randint(0, 9999):04d}"
        country = random.choice(_COUNTRIES)
        amount = round(random.uniform(150, 4000), 2)
        n_attempts = random.choice([3, 4])
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(8.0, 40.0))
            is_last = i == n_attempts - 1
            outcome = AttemptOutcome.AUTHORIZED if is_last else AttemptOutcome.DECLINED
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=account,
                    card_bin=card_bin,
                    card_last4=card_last4,
                    card_network=random.choice(["visa", "mastercard"]),
                    amount=amount,
                    currency="INR",
                    outcome=outcome,
                    decline_reason=None if is_last else random.choice(["invalid_cvv", "invalid_expiry"]),
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=False,
                    attack_type=AttackType.NONE,
                )
            )
    return events + attack


def inject_flash_sale_shopper(events: list[PaymentAttemptEvent], n_cases: int) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a legitimate but elevated-velocity actor: a real
    shopper buying several items in quick succession during a sale.
    Labeled is_abuse=False, attack_type=NONE.

    Hard negative -- superficially resembles card-testing velocity
    (one actor, several attempts, tighter-than-baseline spacing) without
    being abuse: high authorization rate, one or two real saved cards,
    human-paced (10-45s apart) rather than bot-paced.
    """
    attack = []
    for _ in range(n_cases):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        account = f"acct_{_rand_hex(10)}"
        country = random.choice(_COUNTRIES)
        cards = [(random.choice(_TEST_BIN_POOL), f"{random.randint(0, 9999):04d}") for _ in range(random.choice([1, 1, 2]))]
        n_attempts = random.randint(6, 10)
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(10.0, 45.0))
            outcome = random.choices(
                [AttemptOutcome.AUTHORIZED, AttemptOutcome.DECLINED], weights=[0.9, 0.1]
            )[0]
            card_bin, card_last4 = random.choice(cards)
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=account,
                    card_bin=card_bin,
                    card_last4=card_last4,
                    card_network=random.choice(["visa", "mastercard"]),
                    amount=round(random.uniform(200, 3000), 2),
                    currency="INR",
                    outcome=outcome,
                    decline_reason=(
                        None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_BASELINE_DECLINE_REASONS)
                    ),
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=False,
                    attack_type=AttackType.NONE,
                )
            )
    return events + attack


def inject_insufficient_funds_retry(events: list[PaymentAttemptEvent], n_cases: int) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a legitimate retry pattern where every attempt fails
    for a real, unfixable-by-retry reason (insufficient_funds) -- unlike
    inject_legit_retry_burst, this case does not necessarily end in a
    success, and sometimes switches to a second card. Labeled
    is_abuse=False, attack_type=NONE.

    Hard negative -- a genuinely bad failure_ratio (up to 100%) from a
    real customer, testing whether the detector distinguishes "this
    actor's cards keep failing for a mundane reason" from card-testing.
    """
    attack = []
    for _ in range(n_cases):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        account = f"acct_{_rand_hex(10)}"
        country = random.choice(_COUNTRIES)
        n_attempts = random.randint(2, 4)
        switches_card = random.random() < 0.4
        first_bin = random.choice(_TEST_BIN_POOL)
        second_bin = random.choice([b for b in _TEST_BIN_POOL if b != first_bin])
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        eventually_succeeds = random.random() < 0.5
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(10.0, 60.0))
            is_last = i == n_attempts - 1
            use_second_bin = switches_card and i >= n_attempts // 2
            success = is_last and eventually_succeeds
            outcome = AttemptOutcome.AUTHORIZED if success else AttemptOutcome.DECLINED
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=account,
                    card_bin=second_bin if use_second_bin else first_bin,
                    card_last4=f"{random.randint(0, 9999):04d}",
                    card_network=random.choice(["visa", "mastercard"]),
                    amount=round(random.uniform(150, 4000), 2),
                    currency="INR",
                    outcome=outcome,
                    decline_reason=None if success else "insufficient_funds",
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=False,
                    attack_type=AttackType.NONE,
                )
            )
    return events + attack


def inject_card_testing_low_and_slow(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing sequences spread across hours instead of
    seconds, with a moderate (not near-100%) failure rate, labeled
    CARD_TESTING_LOW_AND_SLOW.

    Hard positive -- deliberately evades check_velocity (default 60s
    window) and, with failure_rate held under check_failure_ratio's 0.7
    default threshold, evades that rule too. Only the elevated attempt
    volume vs. the population baseline remains as a signal, which the
    current rule set has no dedicated check for -- this case exists to
    honestly test that gap, not to be guaranteed-caught.
    """
    attack = []
    for _ in range(n_attacks):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        n_attempts = random.randint(15, 25)
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 48))
        for i in range(n_attempts):
            ts = start + timedelta(minutes=i * random.uniform(8.0, 22.0))
            outcome = random.choices(
                [AttemptOutcome.DECLINED, AttemptOutcome.AUTHORIZED], weights=[0.6, 0.4]
            )[0]
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=None,
                    card_bin=random.choice(_TEST_BIN_POOL),
                    card_last4=f"{random.randint(0, 9999):04d}",
                    card_network=random.choice(["visa", "mastercard"]),
                    amount=round(random.uniform(1, 50), 2),
                    currency="INR",
                    outcome=outcome,
                    decline_reason=(
                        None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_ATTACK_DECLINE_REASONS)
                    ),
                    ip_country=random.choice(_COUNTRIES),
                    account_country=None,
                    source=EventSource.SYNTHETIC,
                    is_abuse=True,
                    attack_type=AttackType.CARD_TESTING_LOW_AND_SLOW,
                )
            )
    return events + attack


def inject_bin_list_reuse(events: list[PaymentAttemptEvent], n_attacks: int) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing sequences that cycle a small fixed pool
    of stolen-looking BINs in random order (not incrementing) with a
    moderate failure rate, labeled BIN_LIST_REUSE.

    Hard positive -- deliberately evades check_bin_sequencing (no
    incremental run) and, with failure_rate under 0.7, evades
    check_failure_ratio too. Bot-paced timing means check_velocity is
    still expected to catch it; this case tests whether the other two
    rules correctly stay silent while velocity alone carries detection.
    """
    attack = []
    for _ in range(n_attacks):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        stolen_bins = random.sample(range(400000, 599999), 8)
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        n_attempts = random.randint(30, 40)
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(0.5, 3.0))
            outcome = random.choices(
                [AttemptOutcome.DECLINED, AttemptOutcome.AUTHORIZED], weights=[0.62, 0.38]
            )[0]
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=None,
                    card_bin=f"{random.choice(stolen_bins):06d}",
                    card_last4=f"{random.randint(0, 9999):04d}",
                    card_network="visa",
                    amount=round(random.uniform(1, 100), 2),
                    currency="INR",
                    outcome=outcome,
                    decline_reason=(
                        None if outcome == AttemptOutcome.AUTHORIZED else random.choice(_ATTACK_DECLINE_REASONS)
                    ),
                    ip_country=random.choice(_COUNTRIES),
                    account_country=None,
                    source=EventSource.SYNTHETIC,
                    is_abuse=True,
                    attack_type=AttackType.BIN_LIST_REUSE,
                )
            )
    return events + attack


def build_dataset(
    seed: int,
    n_baseline: int = 2000,
    n_velocity_attacks: int = 3,
    n_bin_attacks: int = 3,
    n_stuffing_attacks: int = 3,
    n_low_and_slow_attacks: int = 3,
    n_bin_reuse_attacks: int = 3,
    n_retry_bursts: int = 15,
    n_flash_sale_cases: int = 12,
    n_insufficient_funds_cases: int = 12,
    attack_size: int = 40,
) -> list[PaymentAttemptEvent]:
    """Assemble one full labeled dataset: baseline traffic + several
    independent injected attack sequences (both easy, signature-shaped
    attacks and harder evasive variants) + legitimate hard-negative edge
    cases, shuffled.
    """
    rng_state = random.getstate()
    random.seed(seed)
    try:
        events = generate_baseline_traffic(n_baseline)
        for _ in range(n_velocity_attacks):
            events = inject_card_testing_velocity(events, attack_size)
        for _ in range(n_bin_attacks):
            events = inject_bin_sequencing(events, attack_size)
        for _ in range(n_stuffing_attacks):
            events = inject_credential_stuffing(events, attack_size)
        events = inject_card_testing_low_and_slow(events, n_low_and_slow_attacks)
        events = inject_bin_list_reuse(events, n_bin_reuse_attacks)
        events = inject_legit_retry_burst(events, n_retry_bursts)
        events = inject_flash_sale_shopper(events, n_flash_sale_cases)
        events = inject_insufficient_funds_retry(events, n_insufficient_funds_cases)
        random.shuffle(events)
    finally:
        random.setstate(rng_state)
    return events


def save_dataset(events: list[PaymentAttemptEvent], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(e.model_dump_json() + "\n")


def load_dataset(path: str) -> list[PaymentAttemptEvent]:
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(PaymentAttemptEvent(**json.loads(line)))
    return events


if __name__ == "__main__":
    dev = build_dataset(seed=1)
    heldout = build_dataset(seed=2)
    save_dataset(dev, "data/datasets/dev.jsonl")
    save_dataset(heldout, "data/datasets/heldout.jsonl")
    n_dev_abuse = sum(1 for e in dev if e.is_abuse)
    n_heldout_abuse = sum(1 for e in heldout if e.is_abuse)
    print(f"dev.jsonl: {len(dev)} events, {n_dev_abuse} labeled abuse")
    print(f"heldout.jsonl: {len(heldout)} events, {n_heldout_abuse} labeled abuse")
