"""Precision/recall/FP-rate and the $-cost model.

Computed only against the held-out labeled set that detection rules
were never tuned on (CLAUDE.md hard constraint) -- detection/rules.py's
thresholds were tuned by looking at data/datasets/dev.jsonl only; see
eval/run_eval.py for the honesty check that confirmed one such tweak
generalized to heldout.jsonl before it was kept.

$-cost model:
- false positive cost = value of a wrongly blocked legitimate customer
  (lost order value + support/goodwill cost)
- false negative cost = fraud loss from a missed card-testing/
  credential-stuffing attempt that went through
Both costs are parameters, not hardcoded, so the eval can be rerun
under different cost assumptions.
"""

from __future__ import annotations


def precision_recall(predictions: list[bool], labels: list[bool]) -> dict:
    """Compute precision, recall, and FP-rate against held-out labels.

    `predictions[i]` is True if actor i was flagged (any action besides
    no_action); `labels[i]` is True if actor i actually had an injected
    attack event.
    """
    tp = fp = tn = fn = 0
    for pred, actual in zip(predictions, labels):
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and not actual:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "fp_rate": fp_rate,
    }


def fp_cost_model(predictions: list[bool], labels: list[bool], fp_cost: float, fn_cost: float) -> dict:
    """Compute total $-cost given per-FP and per-FN cost assumptions."""
    m = precision_recall(predictions, labels)
    total_fp_cost = m["fp"] * fp_cost
    total_fn_cost = m["fn"] * fn_cost
    return {
        "fp_count": m["fp"],
        "fn_count": m["fn"],
        "fp_unit_cost": fp_cost,
        "fn_unit_cost": fn_cost,
        "total_fp_cost": total_fp_cost,
        "total_fn_cost": total_fn_cost,
        "total_cost": total_fp_cost + total_fn_cost,
    }
