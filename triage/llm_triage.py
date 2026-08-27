"""Local LLM (Ollama) explain/rank layer -- read-only, cannot act.

Takes already-flagged ActorEvaluation objects (post policy/engine.py --
decision.action != no_action) and produces a plain-language explanation
for a human analyst, ranked highest-confidence first. This module
imports nothing from policy.engine's decision path and nothing mutating
from integrations.razorpay_client -- it has no access to anything that
executes a decision, by construction, not just by convention. It reads
rule evidence and writes an explanation string; it cannot change
decision.action.

Runs against a local Ollama server (default http://localhost:11434,
model qwen2.5:7b-instruct -- see config.py / .env) instead of a paid
hosted API, per project decision to avoid API cost during development.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from config import settings
from detection.pipeline import ActorEvaluation

_SYSTEM_PROMPT = (
    "You are a fraud-triage assistant for a payments risk analyst. You are given "
    "the deterministic rule evidence and confidence score for one actor already "
    "flagged by a rules engine -- you do not decide or change the action, you only "
    "explain it in plain language for the analyst reviewing the queue. Be concise "
    "(2-4 sentences), reference the specific evidence numbers, and if the pattern "
    "looks like it could be a legitimate customer (e.g. a real retry after a typo) "
    "say so plainly instead of assuming malice."
)


@dataclass
class TriageExplanation:
    actor: str
    action: str
    confidence: float
    explanation: str


def _evidence_summary(evaluation: ActorEvaluation) -> str:
    fired = [r for r in evaluation.rule_results if r.fired]
    lines = [f"- {r.rule_name}: {r.evidence}" for r in fired]
    return "\n".join(lines) if lines else "(no rules fired)"


def _call_ollama(prompt: str) -> str:
    try:
        response = requests.post(
            f"{settings.ollama_host}/api/chat",
            json={
                "model": settings.ollama_model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=60,
        )
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            f"Could not reach Ollama at {settings.ollama_host} -- is `ollama serve` running? "
            f"(OLLAMA_HOST in .env if it's elsewhere)"
        ) from e
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Ollama at {settings.ollama_host} didn't respond within 60s") from e
    response.raise_for_status()
    try:
        return response.json()["message"]["content"].strip()
    except (KeyError, ValueError) as e:
        raise RuntimeError(
            f"Unexpected response shape from Ollama -- is model '{settings.ollama_model}' pulled? "
            f"(`ollama pull {settings.ollama_model}`). Raw response: {response.text[:300]}"
        ) from e


def explain_and_rank(evaluations: list[ActorEvaluation]) -> list[TriageExplanation]:
    """Produce a plain-language explanation for each flagged ActorEvaluation,
    ranked highest-confidence first. Explain only -- no side effects, no
    access to the policy/decision path.
    """
    flagged = [ev for ev in evaluations if ev.decision.action.value != "no_action"]
    flagged.sort(key=lambda ev: ev.confidence, reverse=True)

    results = []
    for ev in flagged:
        prompt = (
            f"Actor: {ev.actor}\n"
            f"Action taken by the policy engine: {ev.decision.action.value} (dry_run={ev.decision.dry_run})\n"
            f"Confidence score: {ev.confidence:.2f}\n"
            f"Rules fired:\n{_evidence_summary(ev)}\n"
            f"Number of events in window: {len(ev.events)}\n\n"
            "Explain this flag for the analyst."
        )
        explanation = _call_ollama(prompt)
        results.append(
            TriageExplanation(
                actor=ev.actor,
                action=ev.decision.action.value,
                confidence=ev.confidence,
                explanation=explanation,
            )
        )
    return results
