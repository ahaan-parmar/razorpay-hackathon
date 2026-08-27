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


def inject_legit_microtransaction_burst(events: list[PaymentAttemptEvent], n_cases: int) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a legitimate high-frequency actor: a real customer
    topping up in-game currency / making several small purchases back to
    back, tight enough to cross check_velocity's 60s/5-attempt threshold
    on its own. Labeled is_abuse=False, attack_type=NONE.

    Hard negative -- unlike inject_flash_sale_shopper (10-45s spacing,
    usually under the velocity threshold), this one is spaced tightly
    enough (5-9s apart) to guarantee check_velocity fires alone. High
    success rate and a single real card keep failure_ratio and
    bin_sequencing silent, so this specifically tests whether one rule
    firing (velocity) on a legitimate actor stays bounded to
    flag_for_review/hold_for_verification rather than soft_decline.
    """
    attack = []
    for _ in range(n_cases):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        account = f"acct_{_rand_hex(10)}"
        country = random.choice(_COUNTRIES)
        card_bin, card_last4 = random.choice(_TEST_BIN_POOL), f"{random.randint(0, 9999):04d}"
        n_attempts = random.randint(5, 9)
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(5.0, 9.0))
            outcome = random.choices(
                [AttemptOutcome.AUTHORIZED, AttemptOutcome.DECLINED], weights=[0.95, 0.05]
            )[0]
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
                    amount=round(random.uniform(20, 300), 2),
                    currency="INR",
                    outcome=outcome,
                    decline_reason=None if outcome == AttemptOutcome.AUTHORIZED else "insufficient_funds",
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=False,
                    attack_type=AttackType.NONE,
                )
            )
    return events + attack


def inject_credential_stuffing_evasive(events: list[PaymentAttemptEvent], n_attacks: int) -> list[PaymentAttemptEvent]:
    """Inject n_attacks credential-stuffing sequences that route through a
    residential proxy matching each stolen account's home country (so
    ip_country == account_country every time) and use a moderate 55%
    failure rate, labeled CREDENTIAL_STUFFING_EVASIVE.

    Hard positive -- a more sophisticated attacker than
    inject_credential_stuffing: deliberately evades check_geo_mismatch
    (no mismatch at all, vs. the original's incidental ~5/6 mismatch
    rate from independently-random countries) and, with failure_rate
    under 0.7, evades check_failure_ratio too. Only
    check_device_session_reuse (many distinct accounts, one device/
    session) and check_velocity are expected to still catch it.
    """
    attack = []
    for _ in range(n_attacks):
        ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
        start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        n_attempts = random.randint(30, 40)
        for i in range(n_attempts):
            ts = start + timedelta(seconds=i * random.uniform(0.5, 3.0))
            outcome = random.choices(
                [AttemptOutcome.FAILED, AttemptOutcome.AUTHORIZED], weights=[0.55, 0.45]
            )[0]
            country = random.choice(_COUNTRIES)
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
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=True,
                    attack_type=AttackType.CREDENTIAL_STUFFING_EVASIVE,
                )
            )
    return events + attack


def inject_distributed_fingerprint_testing(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing operations split across several distinct
    device_fingerprint/session_id pairs sharing one ip_address, each doing
    only a handful of attempts, labeled DISTRIBUTED_FINGERPRINT_TESTING.

    Hard positive that targets the actor-grouping design itself, not a
    single rule: detection/baseline.py's actor_key() groups by
    device_fingerprint, falling back to ip_address only when
    device_fingerprint is absent. An attacker rotating fingerprints
    while reusing one IP (a real anti-fraud evasion technique) is
    therefore split into several small, unremarkable per-fingerprint
    groups that individually never cross any rule's threshold -- this
    case exists to honestly test that structural gap, not to be
    guaranteed-caught.
    """
    attack = []
    for _ in range(n_attacks):
        ip = _rand_ip()
        n_identities = random.randint(5, 8)
        for _ident in range(n_identities):
            device, session = _rand_hex(20), _rand_hex(24)
            # kept below 5 deliberately -- check_velocity/check_failure_ratio/
            # check_timing_regularity all require >5 attempts (or min_attempts=5)
            # to fire, so each per-fingerprint sub-group is invisible to every
            # single-actor rule on its own by construction
            n_attempts = random.randint(3, 4)
            start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 6))
            for i in range(n_attempts):
                ts = start + timedelta(seconds=i * random.uniform(1.0, 4.0))
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
                        attack_type=AttackType.DISTRIBUTED_FINGERPRINT_TESTING,
                    )
                )
    return events + attack


def inject_shared_ip_household(events: list[PaymentAttemptEvent], n_cases: int) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a legitimate shared-IP scenario: 3-5 distinct
    device fingerprints (household or small-office members) transacting
    independently from one IP over about a week, labeled is_abuse=False,
    attack_type=NONE.

    Hard negative built specifically to stress-test IP-level correlation
    (a planned second grouping dimension, alongside the existing
    device_fingerprint-primary grouping -- see README). Each member's
    own behavior is unremarkable on every existing signal (1-4 attempts,
    ~92% success, one real card each, no BIN pattern), and each member
    gets a distinct account_id, matching real distinct users rather than
    one person switching devices. Start times are independently random
    within the window rather than deliberately spread apart or
    deliberately clustered, so some cases will have members who happen
    to transact within the same few hours purely by chance -- an honest
    test of whatever tight-window threshold the new rule ends up using,
    not an artificially easy or artificially hard case.
    """
    attack = []
    for _ in range(n_cases):
        ip = _rand_ip()
        n_members = random.randint(3, 5)
        window_start = datetime.now(timezone.utc) - timedelta(days=random.uniform(1, 14))
        for _member in range(n_members):
            device, session = _rand_hex(20), _rand_hex(24)
            account = f"acct_{_rand_hex(10)}"
            card_bin, card_last4 = random.choice(_TEST_BIN_POOL), f"{random.randint(0, 9999):04d}"
            country = random.choice(_COUNTRIES)
            n_attempts = random.randint(1, 4)
            member_start = window_start + timedelta(hours=random.uniform(0, 7 * 24))
            for i in range(n_attempts):
                ts = member_start + timedelta(hours=i * random.uniform(2, 30))
                outcome = random.choices(
                    [AttemptOutcome.AUTHORIZED, AttemptOutcome.DECLINED], weights=[0.92, 0.08]
                )[0]
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
                        amount=round(random.uniform(150, 5000), 2),
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


def inject_fingerprint_floor_evasion(events: list[PaymentAttemptEvent], n_attacks: int) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing operations split across exactly 3 distinct
    device_fingerprint/session_id pairs sharing one ip_address -- at, not
    above, check_ip_cluster_activity's `min_fingerprints` floor -- labeled
    FINGERPRINT_FLOOR_EVASION.

    Hard positive targeting residual gap #1 from the README
    ("Fingerprint-count floor"): check_ip_cluster_activity only fires
    when a cluster exceeds `min_fingerprints` (default 3) distinct
    fingerprints in-window. This case holds the fingerprint count at
    exactly 3 (the rule's own condition is `fp_count > min_fingerprints`,
    so 3 never trips it) while keeping each fingerprint's own volume
    (3-4 attempts) below every per-actor rule's threshold too, and all 3
    identities active within roughly the same hour so they are
    unambiguously inside one 4-hour window together. Deliberately
    constructed to be invisible to both grouping dimensions shipped so
    far -- this case exists to honestly test that gap, not to be
    guaranteed-caught.
    """
    attack = []
    for _ in range(n_attacks):
        ip = _rand_ip()
        window_start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        for _ident in range(3):
            device, session = _rand_hex(20), _rand_hex(24)
            n_attempts = random.randint(3, 4)
            start = window_start + timedelta(minutes=random.uniform(0, 45))
            for i in range(n_attempts):
                ts = start + timedelta(seconds=i * random.uniform(1.0, 4.0))
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
                        attack_type=AttackType.FINGERPRINT_FLOOR_EVASION,
                    )
                )
    return events + attack


def inject_fingerprint_rotation_slow_paced(
    events: list[PaymentAttemptEvent], n_attacks: int
) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing operations split across 5-8 distinct
    device_fingerprint/session_id pairs sharing one ip_address, like
    inject_distributed_fingerprint_testing, but with each identity's
    short burst introduced 5-7 hours apart -- wider than
    check_ip_cluster_activity's 4-hour window -- labeled
    FINGERPRINT_ROTATION_SLOW_PACED.

    Hard positive targeting residual gap #2 from the README ("Pacing
    beyond the window"): the sliding window fixes the bucket-boundary
    failure mode, but does nothing against an attacker who paces
    fingerprint introduction slower than the window itself. At any given
    moment at most 1-2 identities are ever active in the same 4-hour
    window, even though the campaign totals 5-8 identities over 1-2+
    days -- this case exists to honestly test that gap, not to be
    guaranteed-caught.
    """
    attack = []
    for _ in range(n_attacks):
        ip = _rand_ip()
        n_identities = random.randint(5, 8)
        campaign_start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(48, 96))
        for ident in range(n_identities):
            device, session = _rand_hex(20), _rand_hex(24)
            n_attempts = random.randint(3, 4)
            start = campaign_start + timedelta(hours=ident * random.uniform(5.0, 7.0))
            for i in range(n_attempts):
                ts = start + timedelta(seconds=i * random.uniform(1.0, 4.0))
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
                        attack_type=AttackType.FINGERPRINT_ROTATION_SLOW_PACED,
                    )
                )
    return events + attack


def inject_ip_fingerprint_rotation(events: list[PaymentAttemptEvent], n_attacks: int) -> list[PaymentAttemptEvent]:
    """Inject n_attacks card-testing operations split across 5-8 identities
    that each rotate BOTH ip_address and device_fingerprint/session_id
    together (e.g. a residential proxy pool), all within a several-hour
    campaign window, labeled IP_FINGERPRINT_ROTATION.

    Hard positive targeting residual gap #3 from the README ("IP
    rotation is not addressed at all"): unlike
    inject_distributed_fingerprint_testing (one shared IP, many
    fingerprints), each identity here gets its own IP as well, so
    group_by_ip never merges any of them into a cluster either --
    invisible to both grouping dimensions simultaneously. This case
    exists to honestly test that gap, not to be guaranteed-caught.
    """
    attack = []
    for _ in range(n_attacks):
        n_identities = random.randint(5, 8)
        campaign_start = datetime.now(timezone.utc) - timedelta(hours=random.uniform(0, 72))
        for ident in range(n_identities):
            ip, device, session = _rand_ip(), _rand_hex(20), _rand_hex(24)
            n_attempts = random.randint(3, 4)
            start = campaign_start + timedelta(minutes=ident * random.uniform(15.0, 45.0))
            for i in range(n_attempts):
                ts = start + timedelta(seconds=i * random.uniform(1.0, 4.0))
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
                        attack_type=AttackType.IP_FINGERPRINT_ROTATION,
                    )
                )
    return events + attack


def inject_large_office_network(events: list[PaymentAttemptEvent], n_cases: int) -> list[PaymentAttemptEvent]:
    """Inject n_cases of a legitimate large shared-IP scenario: 10-15
    distinct device fingerprints (a big office or NAT) transacting
    independently from one IP over about two weeks, PLUS a coincidental
    correlated-failure event -- a subset of members sharing one
    now-expired corporate card, all declined within the same afternoon
    -- labeled is_abuse=False, attack_type=NONE.

    Hard negative targeting the README's residual gap #4 ("untested
    scale on the hard negative itself"): inject_shared_ip_household only
    covers 3-5 members with independently random failures; this covers
    10-15 members AND deliberately clusters several members' failures
    into the same narrow window (same card, same reason, same
    afternoon) -- the specific plausible false-positive shape flagged as
    untested, not a softened version of it.
    """
    attack = []
    for _ in range(n_cases):
        ip = _rand_ip()
        n_members = random.randint(10, 15)
        window_start = datetime.now(timezone.utc) - timedelta(days=random.uniform(1, 14))
        members = []
        for _member in range(n_members):
            device, session = _rand_hex(20), _rand_hex(24)
            account = f"acct_{_rand_hex(10)}"
            country = random.choice(_COUNTRIES)
            members.append((device, session, account, country))

        # Normal, independent usage for every member across the window --
        # same shape as inject_shared_ip_household, just more members.
        for device, session, account, country in members:
            n_attempts = random.randint(1, 4)
            member_start = window_start + timedelta(hours=random.uniform(0, 14 * 24))
            for i in range(n_attempts):
                ts = member_start + timedelta(hours=i * random.uniform(2, 30))
                outcome = random.choices(
                    [AttemptOutcome.AUTHORIZED, AttemptOutcome.DECLINED], weights=[0.92, 0.08]
                )[0]
                attack.append(
                    PaymentAttemptEvent(
                        event_id=_event_id(),
                        timestamp=ts,
                        ip_address=ip,
                        device_fingerprint=device,
                        session_id=session,
                        account_id=account,
                        card_bin=random.choice(_TEST_BIN_POOL),
                        card_last4=f"{random.randint(0, 9999):04d}",
                        card_network=random.choice(["visa", "mastercard"]),
                        amount=round(random.uniform(150, 5000), 2),
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

        # The coincidental correlated-failure event: several employees
        # sharing one now-expired corporate card, all trying and
        # declining within the same afternoon.
        affected = random.sample(members, k=random.randint(4, 6))
        corporate_bin, corporate_last4 = random.choice(_TEST_BIN_POOL), f"{random.randint(0, 9999):04d}"
        afternoon_start = window_start + timedelta(hours=random.uniform(0, 14 * 24))
        for device, session, account, country in affected:
            ts = afternoon_start + timedelta(minutes=random.uniform(0, 150))
            attack.append(
                PaymentAttemptEvent(
                    event_id=_event_id(),
                    timestamp=ts,
                    ip_address=ip,
                    device_fingerprint=device,
                    session_id=session,
                    account_id=account,
                    card_bin=corporate_bin,
                    card_last4=corporate_last4,
                    card_network="visa",
                    amount=round(random.uniform(500, 4000), 2),
                    currency="INR",
                    outcome=AttemptOutcome.DECLINED,
                    decline_reason="expired_card",
                    ip_country=country,
                    account_country=country,
                    source=EventSource.SYNTHETIC,
                    is_abuse=False,
                    attack_type=AttackType.NONE,
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
    n_stuffing_evasive_attacks: int = 3,
    n_distributed_fingerprint_attacks: int = 3,
    n_fingerprint_floor_evasion_attacks: int = 3,
    n_fingerprint_rotation_slow_paced_attacks: int = 3,
    n_ip_fingerprint_rotation_attacks: int = 3,
    n_retry_bursts: int = 15,
    n_flash_sale_cases: int = 12,
    n_insufficient_funds_cases: int = 12,
    n_microtransaction_cases: int = 12,
    n_shared_ip_household_cases: int = 12,
    n_large_office_cases: int = 8,
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
        events = inject_credential_stuffing_evasive(events, n_stuffing_evasive_attacks)
        events = inject_distributed_fingerprint_testing(events, n_distributed_fingerprint_attacks)
        events = inject_fingerprint_floor_evasion(events, n_fingerprint_floor_evasion_attacks)
        events = inject_fingerprint_rotation_slow_paced(events, n_fingerprint_rotation_slow_paced_attacks)
        events = inject_ip_fingerprint_rotation(events, n_ip_fingerprint_rotation_attacks)
        events = inject_legit_retry_burst(events, n_retry_bursts)
        events = inject_flash_sale_shopper(events, n_flash_sale_cases)
        events = inject_insufficient_funds_retry(events, n_insufficient_funds_cases)
        events = inject_legit_microtransaction_burst(events, n_microtransaction_cases)
        events = inject_shared_ip_household(events, n_shared_ip_household_cases)
        events = inject_large_office_network(events, n_large_office_cases)
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
