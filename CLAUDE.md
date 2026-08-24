# Project: Checkout/Card-Testing Abuse Detector
Razorpay AI Buildathon 2026 — Track 02: AI Risk Manager

## Context

Built for a live buildathon (~10 days). Track 02 asks for a working detector/verifier/
auto-responder for one class of merchant loss, with measured precision/recall on a
held-out test set. Bar: "Every money action explainable, bounded and gated. Honest
metrics including false-positive cost. Strictly defense-only — anything
offense-capable is disqualified."

Competitive note: the track's own example directions (abuse-ring sentinel,
fraud-spike detector, return-risk scorer, chargeback evidence responder) are already
built by many teams, several with GNN-based graph fraud-ring detectors and published
metrics. Do not clone those names or that approach. This project instead targets a
narrower, well-understood attacker pattern the builder has direct professional
experience with: automated card-testing and checkout credential-stuffing against
payment APIs (rapid low-value auth attempts, BIN sequencing, credential-stuffing on
saved payment methods). Differentiate on execution rigor, not on claiming an empty
niche — assume competitors exist everywhere in this buildathon.

## Problem definition

Detect bot-driven abuse of the checkout/payment flow:
- Velocity: auth attempts per IP / device fingerprint / session / card BIN in a
  rolling window
- Failure ratio: abnormally high decline rate from a single actor
- BIN/card sequencing: incremental or patterned card numbers (classic card-testing)
- Device/session reuse across nominally distinct identities
- Timing regularity: bot traffic lacks human jitter
- Geo/IP mismatch vs account history

## Architecture — deterministic core, LLM explains only, never acts

1. **Ingestion** — synthetic transaction/payment events + real Razorpay test-mode
   API calls (Orders + Payments APIs). Verify current request/response shape and
   test card numbers against https://razorpay.com/docs/ — don't hardcode from
   memory, the API may have changed.
2. **Deterministic detection layer** — explicit, inspectable rules + rarity/velocity
   scoring. No black boxes here.
3. **Confidence/differential scoring** — score how far an event deviates from a
   computed baseline (signal-vs-control ratio), not just a binary rule hit. This is
   the layer that separates confirmed abuse from noise.
4. **Policy engine** — maps (rule fired × severity × confidence) → one bounded
   action from a fixed set: `flag_for_review` / `soft_decline` /
   `hold_for_verification` / `no_action`. Dry-run-by-default; a live action requires
   an explicit non-dry-run flag.
5. **LLM triage (Claude)** — explains and ranks flagged events for a human analyst
   in plain language. Structurally cannot call the action layer — it has no access
   to anything that executes a decision.
6. **Audit log** — every event: inputs, rule(s) fired, confidence score, policy
   decision, dry-run/live status, LLM explanation, timestamp. Structured and
   human-readable.

## Hard constraints

- Defense-only. No exploit/attack tooling of any kind — only detection code and a
  synthetic data generator to test the detector against.
- No fabricated or cherry-picked metrics. Precision/recall/FP-rate must come from a
  held-out labeled set never used for rule tuning.
- Must include a $-cost model for false positives (blocked legit customer) vs false
  negatives (fraud loss) — this is explicitly required by the track brief.
- Must actually call Razorpay test-mode APIs, not just run on isolated synthetic
  data.
- Must include one documented "graceful failure": a real borderline case correctly
  held for review instead of wrongly hard-blocked.
- Keep output plain: a readable audit log/table or minimal CLI. No dashboard, no
  frontend polish, no animations — substance over presentation.
- 10-day scope. Don't gold-plate any single layer.

## Suggested stack

Python, FastAPI, pandas/numpy for scoring + eval, Anthropic API for the
explain-only layer, Razorpay Python SDK or direct REST calls for test-mode
integration, a plain script (not a notebook) for synthetic data generation with
labeled ground truth.

## 10-day milestones

1. Repo scaffold, data schema, architecture skeleton
2. Synthetic data generator with injected attack sequences + labels
3–4. Detection rules + confidence/differential scoring engine
5. Razorpay test-mode API integration + audit log storage
6–7. Held-out validation: precision/recall, FP-cost model. Run one honesty check —
   try an improvement, test whether it generalizes on blind data, report the result
   either way even if negative.
8. LLM triage layer (explain/rank only)
9. Graceful-failure case + audit trail cleanup
10. Metrics writeup + demo prep

## Deliverables

- Working repo matching the architecture above
- README: problem statement, ASCII architecture diagram, how to run, metrics table
  (precision/recall/FP-rate/$-cost), the one documented graceful failure, and an
  honest "what we tried that didn't generalize" section
- A reproducible eval script

## How to work with me

- Before writing code, propose a repo structure and file-by-file plan and wait for
  confirmation.
- Work in milestone order, checking in after each phase rather than building
  everything silently.
- If unsure of a Razorpay API detail, say so and ask rather than guessing.
- No speculative features beyond the plan above.