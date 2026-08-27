"""Structured, human-readable audit log.

One record per evaluated event: inputs, rule(s) fired, confidence
score, policy decision, dry-run/live status, LLM explanation (once
triage runs), timestamp. Append-only JSONL so eval/run_eval.py and a
human reading the raw file both work off the same source of truth.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from detection.rules import RuleResult
from policy.engine import PolicyDecision
from schema.events import PaymentAttemptEvent

DEFAULT_LOG_PATH = "audit/logs/audit.jsonl"


def log_event(
    event: PaymentAttemptEvent,
    rule_results: list[RuleResult],
    confidence: float,
    decision: PolicyDecision,
    explanation: str | None = None,
    log_path: str = DEFAULT_LOG_PATH,
) -> None:
    """Append one structured audit record for this evaluated event."""
    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    record = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "event_id": event.event_id,
        "event_timestamp": event.timestamp.isoformat(),
        "actor": event.device_fingerprint or event.ip_address,
        "source": event.source.value,
        "rules_fired": [r.rule_name for r in rule_results if r.fired],
        "rule_evidence": {r.rule_name: r.evidence for r in rule_results if r.fired},
        "confidence": round(confidence, 4),
        "action": decision.action.value,
        "dry_run": decision.dry_run,
        "rationale": decision.rationale,
        "explanation": explanation,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
