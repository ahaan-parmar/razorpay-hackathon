"""Unit tests for audit/logger.py, including the bare-filename edge case
found during self-review (os.makedirs("") used to crash)."""

import json
import os

from audit.logger import log_event
from detection.rules import RuleResult
from policy.engine import Action, PolicyDecision
from schema.events import AttemptOutcome, EventSource, PaymentAttemptEvent
from datetime import datetime, timezone


def _event() -> PaymentAttemptEvent:
    return PaymentAttemptEvent(
        event_id="evt_1",
        timestamp=datetime.now(timezone.utc),
        ip_address="203.0.113.5",
        session_id="sess_1",
        card_bin="411111",
        amount=10.0,
        outcome=AttemptOutcome.DECLINED,
        source=EventSource.SYNTHETIC,
    )


def _decision() -> PolicyDecision:
    return PolicyDecision(
        action=Action.FLAG_FOR_REVIEW, dry_run=True, fired_rules=["velocity"], confidence=0.4, rationale="test"
    )


def test_log_event_with_bare_filename_no_directory(tmp_path, monkeypatch):
    """A log_path with no directory component (os.path.dirname == "") used
    to crash with FileNotFoundError on os.makedirs(""). Run from a temp cwd
    so the bare filename lands somewhere disposable."""
    monkeypatch.chdir(tmp_path)
    log_event(_event(), [RuleResult("velocity", True, "low", {})], 0.4, _decision(), log_path="audit.jsonl")
    assert os.path.exists("audit.jsonl")


def test_log_event_writes_valid_json_record(tmp_path):
    log_path = tmp_path / "nested" / "audit.jsonl"
    log_event(_event(), [RuleResult("velocity", True, "low", {"x": 1})], 0.4, _decision(), log_path=str(log_path))
    with open(log_path) as f:
        record = json.loads(f.readline())
    assert record["event_id"] == "evt_1"
    assert record["rules_fired"] == ["velocity"]
    assert record["action"] == "flag_for_review"
    assert record["dry_run"] is True
