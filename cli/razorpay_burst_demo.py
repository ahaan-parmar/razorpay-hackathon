"""Live demo: fire a bounded burst of real Razorpay test-mode order
creations and run them through the same detection pipeline as synthetic
data, to show check_velocity firing on genuinely live API traffic.

No card data is ever involved -- every event here is a real
POST /v1/orders call (see integrations/razorpay_client.py); this stays
clean of anything offense-capable by construction, not just by intent.
The burst size defaults to a small, bounded n (10) -- this is a demo of
the velocity rule against live traffic, not a load generator.

Requires RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET (test-mode) in .env.

Usage: python -m cli.razorpay_burst_demo --n 10 --amount 10 --interval 2
"""

from __future__ import annotations

import argparse
import time

from audit.logger import log_event
from detection.pipeline import evaluate_batch
from integrations.normalize import razorpay_payment_to_event
from integrations.razorpay_client import create_order
from schema.events import PaymentAttemptEvent


def fire_burst(n: int, amount: float, interval_seconds: float) -> list[PaymentAttemptEvent]:
    events = []
    for i in range(n):
        raw_order = create_order(amount=amount, receipt_id=f"burst_demo_{i}_{int(time.time() * 1000)}")
        events.append(razorpay_payment_to_event(raw_order))
        if i < n - 1:
            time.sleep(interval_seconds)
    return events


def main():
    parser = argparse.ArgumentParser(
        description="Fire a bounded burst of real Razorpay test-mode order creations and run detection on them."
    )
    parser.add_argument("--n", type=int, default=10, help="number of orders to create")
    parser.add_argument("--amount", type=float, default=10.0, help="order amount in rupees")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between order creations")
    args = parser.parse_args()

    print(f"Creating {args.n} real test-mode Razorpay orders, {args.interval}s apart...")
    events = fire_burst(args.n, args.amount, args.interval)
    print(f"Created {len(events)} real orders. Running detection...")

    evaluations = evaluate_batch(events)
    for ev in evaluations:
        for event in ev.events:
            log_event(event, ev.rule_results, ev.confidence, ev.decision)
        print(
            f"actor={ev.actor}  n={len(ev.events)}  action={ev.decision.action.value}  "
            f"confidence={ev.confidence:.2f}  rules={ev.decision.fired_rules}"
        )


if __name__ == "__main__":
    main()
