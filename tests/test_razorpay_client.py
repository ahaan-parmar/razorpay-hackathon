"""Unit tests for integrations/razorpay_client.py's input validation.

Only covers the amount>0 guard, which runs before any network call or
credential check -- no real API keys needed. Actual live API behavior is
verified manually against the real test-mode API (see README), not here.
"""

import pytest

from integrations.razorpay_client import capture_payment, create_order


def test_create_order_rejects_zero_amount():
    with pytest.raises(ValueError):
        create_order(amount=0, receipt_id="r1")


def test_create_order_rejects_negative_amount():
    with pytest.raises(ValueError):
        create_order(amount=-5, receipt_id="r1")


def test_capture_payment_rejects_non_positive_amount():
    with pytest.raises(ValueError):
        capture_payment(payment_id="pay_1", amount=0)
