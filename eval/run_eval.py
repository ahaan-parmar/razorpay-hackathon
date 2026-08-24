"""Reproducible eval entrypoint.

Loads the held-out labeled set (data/datasets/heldout.jsonl, generated
once by data/generate_synthetic.py and frozen -- detection/rules.py's
thresholds were tuned by looking only at data/datasets/dev.jsonl, never
this file), runs it through detection/pipeline.py, and reports
precision/recall/FP-rate plus the $-cost model. This is the script the
README's metrics table is reproduced from.

Cost assumptions (fp_cost, fn_cost) are illustrative, not measured real
merchant figures -- pass --fp-cost/--fn-cost to rerun under different
assumptions. Defaults:
- fp_cost ~ INR 650: an average synthetic order (~INR 2000) times an
  assumed 30% customer-abandons-after-soft-decline rate, plus a flat
  INR 50 support/friction cost.
- fn_cost ~ INR 5000: assumed downstream fraud loss once a card-testing
  actor confirms a card is live (this project does not model the
  card-testing -> larger-fraud conversion rate; it treats every missed
  attack actor as one full loss, which is a deliberately conservative
  upper bound, not a calibrated estimate).
"""

from __future__ import annotations

import argparse

from data.generate_synthetic import load_dataset
from detection.pipeline import evaluate_batch
from eval.metrics import fp_cost_model, precision_recall

HELDOUT_PATH = "data/datasets/heldout.jsonl"


def run(heldout_path: str = HELDOUT_PATH, fp_cost: float = 650.0, fn_cost: float = 5000.0) -> dict:
    events = load_dataset(heldout_path)
    evaluations = evaluate_batch(events)

    predictions = [ev.decision.action.value != "no_action" for ev in evaluations]
    labels = [any(e.is_abuse for e in ev.events) for ev in evaluations]

    metrics = precision_recall(predictions, labels)
    cost = fp_cost_model(predictions, labels, fp_cost=fp_cost, fn_cost=fn_cost)

    return {"n_actors": len(evaluations), "metrics": metrics, "cost": cost}


def main():
    parser = argparse.ArgumentParser(description="Run the held-out eval and print the metrics table.")
    parser.add_argument("--heldout-path", default=HELDOUT_PATH)
    parser.add_argument("--fp-cost", type=float, default=650.0, help="INR cost of one false positive")
    parser.add_argument("--fn-cost", type=float, default=5000.0, help="INR cost of one false negative")
    args = parser.parse_args()

    result = run(args.heldout_path, args.fp_cost, args.fn_cost)
    m, c = result["metrics"], result["cost"]

    print(f"Held-out eval: {result['n_actors']} actors ({args.heldout_path})")
    print(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print(f"  precision={m['precision']:.3f}  recall={m['recall']:.3f}  fp_rate={m['fp_rate']:.3f}")
    print(f"  $-cost @ fp={args.fp_cost:.0f} fn={args.fn_cost:.0f}:")
    print(f"    FP cost total = INR {c['total_fp_cost']:.0f}  ({c['fp_count']} x {c['fp_unit_cost']:.0f})")
    print(f"    FN cost total = INR {c['total_fn_cost']:.0f}  ({c['fn_count']} x {c['fn_unit_cost']:.0f})")
    print(f"    TOTAL cost    = INR {c['total_cost']:.0f}")


if __name__ == "__main__":
    main()
