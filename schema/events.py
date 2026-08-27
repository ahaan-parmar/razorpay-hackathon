"""Canonical event schema for the checkout abuse detector.

PaymentAttemptEvent is the single contract every producer must emit:
data/generate_synthetic.py constructs these directly, and
integrations/normalize.py maps raw Razorpay API responses onto this
same shape. detection/rules.py, detection/scoring.py, and
eval/metrics.py all consume PaymentAttemptEvent and nothing else -- no
producer-specific fields leak past this module. This is what prevents
schema drift between synthetic eval data and live Razorpay demo data
(see CLAUDE.md milestone 6-7 honesty check).

Full card numbers are never modeled or stored here -- only the BIN
(first 6 digits) and last 4, which is what Razorpay's own API exposes
for a payment.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class EventSource(str, Enum):
    SYNTHETIC = "synthetic"
    RAZORPAY_TEST = "razorpay_test"


class AttemptOutcome(str, Enum):
    AUTHORIZED = "authorized"
    DECLINED = "declined"
    FAILED = "failed"


class AttackType(str, Enum):
    """Ground-truth label. Only ever set on synthetic data -- real
    Razorpay events are unlabeled until a human analyst confirms one via
    the audit log."""

    CARD_TESTING_VELOCITY = "card_testing_velocity"
    CARD_TESTING_LOW_AND_SLOW = "card_testing_low_and_slow"
    BIN_SEQUENCING = "bin_sequencing"
    BIN_LIST_REUSE = "bin_list_reuse"
    CREDENTIAL_STUFFING = "credential_stuffing"
    CREDENTIAL_STUFFING_EVASIVE = "credential_stuffing_evasive"
    DISTRIBUTED_FINGERPRINT_TESTING = "distributed_fingerprint_testing"
    FINGERPRINT_FLOOR_EVASION = "fingerprint_floor_evasion"
    FINGERPRINT_ROTATION_SLOW_PACED = "fingerprint_rotation_slow_paced"
    IP_FINGERPRINT_ROTATION = "ip_fingerprint_rotation"
    NONE = "none"


class PaymentAttemptEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime

    # actor identifiers
    ip_address: str = Field(min_length=1)
    device_fingerprint: Optional[str] = None
    session_id: str = Field(min_length=1)
    account_id: Optional[str] = None  # None for guest checkout

    # card identifiers -- BIN + last4 only, never a full PAN
    card_bin: str = Field(min_length=6, max_length=6)
    card_last4: Optional[str] = Field(default=None, min_length=4, max_length=4)
    card_network: Optional[str] = None

    amount: float = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)

    outcome: AttemptOutcome
    decline_reason: Optional[str] = None

    ip_country: Optional[str] = None
    account_country: Optional[str] = None

    source: EventSource
    provider_ref: Optional[str] = None  # Razorpay payment_id/order_id, for traceability

    # ground truth -- populated only for synthetic data
    is_abuse: Optional[bool] = None
    attack_type: Optional[AttackType] = None

    @field_validator("card_bin")
    @classmethod
    def bin_is_digits(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("card_bin must be exactly 6 digits")
        return v

    @field_validator("card_last4")
    @classmethod
    def last4_is_digits(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.isdigit():
            raise ValueError("card_last4 must be exactly 4 digits")
        return v
