"""CLI entrypoint: ingestion -> detection -> policy -> [triage] -> audit.

Plain CLI/table output only -- no dashboard, no frontend polish, per
CLAUDE.md.

Note on --live: this project has no live-action executor -- nothing
here ever actually blocks a real payment or calls back into Razorpay to
act on a decision. --live only changes the dry_run flag recorded on
each PolicyDecision and in the audit log, which is the structural gate
CLAUDE.md's architecture calls for ("dry-run-by-default; a live action
requires an explicit non-dry-run flag"). Wiring an actual blocking
action into a real checkout flow is out of this project's scope by
design -- it is strictly a detector/explainer, not an actor.
"""

from __future__ import annotations

import argparse

from audit.logger import log_event
from data.generate_synthetic import load_dataset
from detection.pipeline import evaluate_batch


def _print_table(evaluations) -> int:
    flagged = [ev for ev in evaluations if ev.decision.action.value != "no_action"]
    flagged.sort(key=lambda ev: ev.confidence, reverse=True)

    header = f"{'actor':<24} {'n':>3} {'action':<22} {'conf':>5}  rules"
    print(header)
    print("-" * len(header))
    for ev in flagged:
        rules = ", ".join(ev.decision.fired_rules) or "-"
        print(f"{ev.actor[:24]:<24} {len(ev.events):>3} {ev.decision.action.value:<22} {ev.confidence:>5.2f}  {rules}")
    return len(flagged)


def main():
    parser = argparse.ArgumentParser(description="Run one end-to-end pass over a batch of events and print the audit table.")
    parser.add_argument("--dataset", default="data/datasets/dev.jsonl")
    parser.add_argument("--live", action="store_true", help="record dry_run=False on decisions (no live action is ever taken -- see module docstring)")
    parser.add_argument("--triage", action="store_true", help="also run the local LLM explain/rank layer (requires Ollama running, see config.py)")
    args = parser.parse_args()

    events = load_dataset(args.dataset)
    evaluations = evaluate_batch(events, dry_run=not args.live)

    explanations = {}
    if args.triage:
        from triage.llm_triage import explain_and_rank

        for exp in explain_and_rank(evaluations):
            explanations[exp.actor] = exp.explanation

    for ev in evaluations:
        explanation = explanations.get(ev.actor)
        for event in ev.events:
            log_event(event, ev.rule_results, ev.confidence, ev.decision, explanation=explanation)

    n_flagged = _print_table(evaluations)
    print(f"\n{len(evaluations)} actors evaluated, {n_flagged} flagged (dry_run={not args.live}).")
    print("Full audit trail: audit/logs/audit.jsonl")


if __name__ == "__main__":
    main()
