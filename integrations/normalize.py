"""Owns raw-Razorpay-response -> PaymentAttemptEvent normalization.

This is the single place that maps Razorpay's Order/Payment JSON shape
onto the canonical schema in schema/events.py. It exists specifically so
that data/generate_synthetic.py (which already emits PaymentAttemptEvent
natively) and integrations/razorpay_client.py (which returns raw
Razorpay dicts) converge on the exact same schema before either reaches
detection/rules.py. If Razorpay's response shape changes, this is the
only file that should need to change.

Two honest limitations, discovered verifying the docs (see
integrations/razorpay_client.py's module docstring), that this module
makes explicit rather than silently papering over:

1. Orders/Payments responses never carry the customer's IP or a session
   identifier -- ip_address is set to the sentinel "0.0.0.0" and
   session_id to the Razorpay order_id. Real events normalized here are
   therefore never meaningfully scored by the geo_mismatch rule and are
   grouped, in effect, one actor per order for the velocity rule -- fine
   for demonstrating a live-traffic burst hits check_velocity, not a
   substitute for the synthetic set's realistic actor grouping.
2. Razorpay's payment/card object exposes `last4` and `network` but
   never a 6-digit BIN/IIN. card_bin is set to the sentinel "000000" so
   the schema's required field is satisfied without fabricating a real
   BIN -- check_bin_sequencing will never fire on normalized Razorpay
   events, by construction, not by chance. Real events also get no
   is_abuse/attack_type label (ground truth only exists for synthetic
   data).
"""

from __future__ import annotations

from datetime import datetime, timezone

from schema.events import AttemptOutcome, EventSource, PaymentAttemptEvent

_NO_CARD_DATA_BIN = "000000"
_NO_IP_SENTINEL = "0.0.0.0"


def razorpay_payment_to_event(raw_order: dict, raw_payment: dict | None = None) -> PaymentAttemptEvent:
    """Map a raw Razorpay order (+ optional payment) API response onto
    PaymentAttemptEvent.

    `raw_payment=None` covers an order that was created but never paid --
    the expected case for the create_order() burst demo, since Razorpay's
    API can't originate a card payment server-side (see module docstring).
    """
    order_id = raw_order["id"]
    amount = raw_order["amount"] / 100  # paise -> rupees
    currency = raw_order["currency"]

    if raw_payment is None:
        return PaymentAttemptEvent(
            event_id=f"rzp_order_{order_id}",
            timestamp=datetime.fromtimestamp(raw_order["created_at"], tz=timezone.utc),
            ip_address=_NO_IP_SENTINEL,
            session_id=order_id,
            card_bin=_NO_CARD_DATA_BIN,
            amount=amount,
            currency=currency,
            outcome=AttemptOutcome.FAILED,
            decline_reason="order_created_no_payment_attempted",
            source=EventSource.RAZORPAY_TEST,
            provider_ref=order_id,
        )

    payment_id = raw_payment["id"]
    status = raw_payment["status"]
    if status in ("authorized", "captured"):
        outcome = AttemptOutcome.AUTHORIZED
    elif status == "failed":
        outcome = AttemptOutcome.FAILED
    else:
        outcome = AttemptOutcome.DECLINED

    card = raw_payment.get("card") or {}
    return PaymentAttemptEvent(
        event_id=f"rzp_payment_{payment_id}",
        timestamp=datetime.fromtimestamp(raw_payment["created_at"], tz=timezone.utc),
        ip_address=_NO_IP_SENTINEL,
        session_id=order_id,
        card_bin=_NO_CARD_DATA_BIN,
        card_last4=card.get("last4"),
        card_network=card.get("network"),
        amount=amount,
        currency=raw_payment.get("currency", currency),
        outcome=outcome,
        decline_reason=raw_payment.get("error_reason"),
        source=EventSource.RAZORPAY_TEST,
        provider_ref=payment_id,
    )
