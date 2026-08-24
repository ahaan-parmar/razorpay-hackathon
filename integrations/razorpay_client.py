"""Thin wrapper over Razorpay's test-mode Orders and Payments REST APIs.

Only ever talks to test-mode -- key material is read from
config.settings, which must hold a test key pair (rzp_test_...).

Verified against https://razorpay.com/docs/ (2026-08):
- POST /v1/orders               -- amount is in the smallest currency
  subunit (paise for INR), so create_order() takes rupees and converts.
- GET  /v1/payments/:id
- POST /v1/payments/:id/capture -- requires amount + currency, only
  valid while the payment is in the `authorized` state.

Important limitation discovered while verifying the docs: Razorpay's
standard Orders/Payments API is card-data-PCI-scoped -- a backend script
cannot POST a raw card number to create a payment attempt (that only
happens through Razorpay's client-side Checkout/hosted mock-bank page),
and even a fetched real payment's nested `card` object does not expose
a 6-digit BIN/IIN, only `last4` and `network`. So this client only ever
creates/reads/captures Orders and Payments -- it never attempts a card
payment itself. integrations/normalize.py documents how this maps onto
PaymentAttemptEvent, including the sentinel used where card_bin isn't
available. Returns raw Razorpay API response dicts; normalize.py is
what turns those into PaymentAttemptEvent, not this module.
"""

from __future__ import annotations

import razorpay

from config import settings

_client: razorpay.Client | None = None


def _get_client() -> razorpay.Client:
    global _client
    if _client is None:
        if not settings.razorpay_key_id or not settings.razorpay_key_secret:
            raise RuntimeError("RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set (see .env.example)")
        if not settings.razorpay_key_id.startswith("rzp_test_"):
            raise RuntimeError("RAZORPAY_KEY_ID must be a test-mode key (rzp_test_...) -- refusing to run against live keys")
        _client = razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))
    return _client


def create_order(amount: float, receipt_id: str, currency: str = "INR") -> dict:
    """Create a real test-mode Razorpay order. `amount` is in rupees (converted
    to paise for the API call). Returns the raw order response dict.
    """
    client = _get_client()
    return client.order.create(
        {
            "amount": round(amount * 100),
            "currency": currency,
            "receipt": receipt_id,
            "payment_capture": 0,
        }
    )


def fetch_payment(payment_id: str) -> dict:
    """Fetch a real payment by id. Returns the raw payment response dict."""
    client = _get_client()
    return client.payment.fetch(payment_id)


def capture_payment(payment_id: str, amount: float, currency: str = "INR") -> dict:
    """Capture a real authorized payment. `amount` is in rupees (converted to
    paise) and must match the original payment amount. Returns the raw
    payment response dict.
    """
    client = _get_client()
    return client.payment.capture(payment_id, round(amount * 100), {"currency": currency})
