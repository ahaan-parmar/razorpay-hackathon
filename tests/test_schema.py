"""Sanity tests for the canonical PaymentAttemptEvent schema."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from schema.events import AttackType, AttemptOutcome, EventSource, PaymentAttemptEvent


def _valid_kwargs(**overrides):
    kwargs = dict(
        event_id="evt_1",
        timestamp=datetime.now(timezone.utc),
        ip_address="203.0.113.5",
        session_id="sess_1",
        card_bin="411111",
        amount=499.0,
        outcome=AttemptOutcome.AUTHORIZED,
        source=EventSource.SYNTHETIC,
    )
    kwargs.update(overrides)
    return kwargs


def test_valid_event_constructs():
    event = PaymentAttemptEvent(**_valid_kwargs())
    assert event.card_bin == "411111"
    assert event.currency == "INR"


def test_card_bin_must_be_six_digits():
    with pytest.raises(ValidationError):
        PaymentAttemptEvent(**_valid_kwargs(card_bin="41111"))

    with pytest.raises(ValidationError):
        PaymentAttemptEvent(**_valid_kwargs(card_bin="41111A"))


def test_card_last4_must_be_four_digits():
    with pytest.raises(ValidationError):
        PaymentAttemptEvent(**_valid_kwargs(card_last4="12A4"))


def test_amount_must_be_positive():
    with pytest.raises(ValidationError):
        PaymentAttemptEvent(**_valid_kwargs(amount=-5))


def test_synthetic_label_fields_optional():
    event = PaymentAttemptEvent(
        **_valid_kwargs(is_abuse=True, attack_type=AttackType.CARD_TESTING_VELOCITY)
    )
    assert event.is_abuse is True
    assert event.attack_type == AttackType.CARD_TESTING_VELOCITY
