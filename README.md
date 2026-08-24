# Checkout/Card-Testing Abuse Detector

Razorpay AI Buildathon 2026 -- Track 02: AI Risk Manager

Detects bot-driven card-testing and credential-stuffing abuse against a
checkout flow via a deterministic rule + scoring layer, a bounded
dry-run-by-default policy engine, and an explain-only LLM triage layer.
See `CLAUDE.md` for the full problem definition, architecture, and hard
constraints.

Status: all 10 milestones complete. Razorpay (milestone 5) and the
triage layer (milestone 8) are both live-verified: `create_order`
against the real test-mode API, and `triage/llm_triage.py` against a
local Ollama model (`qwen2.5:7b-instruct`) instead of a paid hosted API,
to avoid API cost during development.

## Architecture

```
 data/generate_synthetic.py  --\
                                 >--  PaymentAttemptEvent  --\
 integrations/razorpay_client.py                              |
     -> integrations/normalize.py --/                         |
                                                                v
                                          detection/pipeline.py
                                          (group_by_actor, per-actor)
                                                |
                        +-----------------------+-----------------------+
                        v                                               v
              detection/rules.py                          detection/baseline.py
              (6 deterministic checks)                    + detection/scoring.py
              velocity / failure_ratio /                  (population-baseline
              bin_sequencing / device_session_reuse /       signal-vs-control
              timing_regularity / geo_mismatch               confidence, 0-1)
                        \                                               /
                         +-------------------+-------------------------+
                                             v
                                   policy/engine.py
                          (rules x severity x confidence -> action
                           no_action / flag_for_review /
                           hold_for_verification / soft_decline,
                           dry-run by default)
                                             |
                          +------------------+------------------+
                          v                                     v
              triage/llm_triage.py                    audit/logger.py
              (local Ollama model explains            (JSONL: every event,
               + ranks flagged actors --                rules fired, confidence,
               read only, cannot change                 decision, dry-run flag,
               the action)                               explanation)
                                             |
                                     cli/main.py
                              (plain table + audit trail)
```

The LLM never touches the action path: `triage/llm_triage.py` imports
nothing from `policy.engine`'s decision logic and has no access to
anything that executes or mutates a decision.

## How to run

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt        # or .venv/bin/pip on macOS/Linux
cp .env.example .env                                  # fill in RAZORPAY_KEY_ID/SECRET (Ollama vars default to localhost)
ollama pull qwen2.5:7b-instruct                        # or set OLLAMA_MODEL to whatever you have pulled

python -m data.generate_synthetic                      # writes data/datasets/{dev,heldout}.jsonl
python -m cli.main --dataset data/datasets/dev.jsonl    # detection -> policy -> audit trail
python -m cli.main --dataset data/datasets/dev.jsonl --triage   # + local LLM explanations (needs Ollama running)
python -m eval.run_eval                                 # precision/recall/FP-rate/$-cost on the held-out set
python -m pytest tests/                                  # schema sanity tests

# live demo: real Razorpay test-mode Orders API calls (needs RAZORPAY_KEY_ID/SECRET),
# a bounded burst (default n=10) that triggers check_velocity on genuinely live traffic
python -m cli.razorpay_burst_demo --n 10 --amount 10 --interval 2
```

## Metrics

`eval/run_eval.py` against `data/datasets/heldout.jsonl` (2,054 actors,
13 injected attack sequences across 5 attack types, never used to tune
any rule threshold):

| metric | value |
|---|---|
| TP / FP / TN / FN | 13 / 0 / 2039 / 2 |
| precision | 1.000 |
| recall | 0.867 |
| FP rate | 0.000 |
| $-cost (fp=INR 650, fn=INR 5000) | INR 10,000 (2 FN x 5000, 0 FP) |

**Why recall isn't 1.0, and why that's the honest number.** An earlier
version of this eval scored a clean 1.000/1.000 on both dev and
heldout. That was a red flag, not a result: the synthetic attack
generator was encoding the exact same signals the rules check for
(sub-3-second timing, >85% failure rate, one actor per attack), so the
classes were trivially separable rather than realistically tested. The
datasets were hardened with:

- **Hard negatives** (labeled `is_abuse=False`, meant to *not* trigger
  action): `inject_flash_sale_shopper` -- a real shopper buying 6-10
  items 10-45s apart; `inject_insufficient_funds_retry` -- a real
  customer whose card keeps failing for a mundane reason, sometimes
  never succeeding.
- **Hard positives** (labeled `is_abuse=True`, meant to be genuinely
  harder to catch): `inject_bin_list_reuse` -- a stolen-card list
  cycled in random (non-incrementing) order with a 62% failure rate,
  under `check_failure_ratio`'s 0.7 threshold; `inject_card_testing_low_and_slow`
  -- 15-25 attempts spread across hours with a 60% failure rate, evading
  both `check_velocity`'s 60-second window and the failure-ratio
  threshold.

Result: **all 12 hard negatives correctly resolved to `no_action`** on
both dev and heldout (precision held at 1.000, FP rate 0.000) -- even
though several reached confidence scores up to 0.75, the policy engine
never acts when zero rules have fired, by design. **The low-and-slow
attacks are the real gap**: 2 of 3 (heldout) / 3 of 3 (dev) evaded every
rule outright, landing at confidence ~0.46-0.50 with nothing fired. The
one low-and-slow instance that *was* caught was luck, not design -- its
random decline rate happened to drift to 0.75, just over the 0.7
threshold. `bin_list_reuse` was caught every time, but only via
`check_velocity` (its bot-paced timing survives); `check_bin_sequencing`
and `check_failure_ratio` correctly stayed silent on it exactly as
designed, confirming those two rules were cleanly evaded without
velocity backstopping the whole detector.

**Honest conclusion**: this rule set has no signal for volume spread
over hours rather than minutes -- an attacker patient enough to test
cards over a multi-hour window with a moderate failure rate currently
gets through. A longer-window velocity check (e.g. attempts per actor
per 4-hour window) is the natural next rule to add; it was not added
here so this gap could be reported honestly rather than patched away
right before the numbers were taken.

## One honesty check (milestone 6-7)

Before the hardening above, the dev set's original `inject_legit_retry_burst`
cases (a real customer failing CVV entry 2-3 times, then succeeding)
were producing false positives: 6 of the (then) legit-retry-shaped
actors on dev, 7 on heldout, landed at `hold_for_verification` or
`flag_for_review` via `check_failure_ratio` (3-4 attempts, 1-3
failures = up to 0.75 failure ratio, over the 0.7 threshold, with
`min_attempts=3`). Precision on dev was 0.600, on heldout 0.562;
recall was 1.000 on both.

**Improvement tried**: raise `check_failure_ratio`'s `min_attempts`
from 3 to 5, tuned by looking at dev only.

**Tested on heldout (never touched during tuning)**: precision and
recall both reached 1.000/1.000 with zero FPs and zero FNs -- the
improvement generalized. It's now the shipped default
(`detection/rules.py`, `check_failure_ratio`).

**Caveat on this result, reported honestly**: dev and heldout are drawn
from the same synthetic generator on different seeds, so this is a
weaker generalization test than validating against a genuinely
independent distribution (e.g. real traffic) would be -- it rules out
overfitting to the specific random draw, not overfitting to the
generator's assumptions as a whole.

## Graceful failure

The `check_failure_ratio` false positives above, before the
`min_attempts` fix, are this project's documented graceful failure: a
real, non-malicious pattern (a customer mistyping their CVV twice
before succeeding) tripped a detection rule, but the bounded policy
engine never hard-blocked it. `soft_decline` requires >=2 rules fired
or confidence >=0.8; this case fired exactly 1 rule at confidence
~0.44-0.66, so the worst outcome it ever produced was
`hold_for_verification` (an extra verification step) or
`flag_for_review` (a human looks, nothing is blocked) -- never a lost
sale. After the fix, the same case resolves cleanly to `no_action`.

The bound held even under a harder, adversarial version of the same
idea: in the hardened heldout set, `inject_insufficient_funds_retry`
includes cases where the customer's card *never* succeeds (every
attempt genuinely declined) -- a worse failure_ratio than the original
CVV-typo case. Under the current default (`min_attempts=5`, and these
cases cap at 4 attempts) it never even reaches the rule; confidence
alone reached 0.75 with zero rules fired, and `no_action` was correctly
never overridden by a confidence score with no rule behind it.

## What we tried that didn't generalize

Nothing tried so far failed to generalize -- the one threshold change
tested (`min_attempts` 3->5, above) held up on the held-out set. The
one confirmed gap found by hardening the eval (low-and-slow card
testing, above) was not something "tried and abandoned" -- it's an
honestly reported detection gap in the current rule set, not a fix that
regressed.
