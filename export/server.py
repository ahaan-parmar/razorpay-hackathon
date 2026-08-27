"""Read-only data-export API, plus the static GUI that consumes it.

Exposes the audit log and current eval metrics as stable, typed JSON --
GET /audit and GET /metrics -- so a frontend can read this project's
output without importing or touching any pipeline internals (schema/,
detection/, policy/, integrations/, eval/). web/index.html is that
frontend, served from this same app so it's same-origin (no CORS
dependency, and no localhost-fetch problem the way a sandboxed Claude
Artifact would have) -- but export/schemas.py's typed models are still
the real contract; nothing about web/ is special-cased in what data it
can see.

Strictly read-only: every route is GET, nothing here writes to the
audit log, calls Razorpay, calls the LLM triage layer, or reaches
policy/engine.py's decision path -- it only reads what those layers
already produced. No new capability is added to the system by this
file; it is a view onto existing outputs.

Run:  uvicorn export.server:app --reload --port 8000 --host 127.0.0.1
UI:   http://127.0.0.1:8000/
Docs: http://127.0.0.1:8000/docs (auto-generated OpenAPI schema, kept
in sync with export/schemas.py by FastAPI itself -- that page is the
actual source of truth for the response shape, not this docstring).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from audit.logger import DEFAULT_LOG_PATH
from eval.run_eval import HELDOUT_PATH
from eval.run_eval import run as run_eval
from export.schemas import AuditRecordOut, ConfusionMatrixOut, CostBreakdownOut, MetricsOut

_WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

app = FastAPI(title="Checkout Abuse Detector -- Data Export", version="1.0.0")

# This server only ever runs on localhost reading local files -- it is not
# meant to be exposed over a network, so a permissive local-dev CORS policy
# is fine here. No credentials/cookies are used, so allow_origins=["*"] is
# valid under CORS rules (browsers only reject "*" when allow_credentials=True).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/audit", response_model=list[AuditRecordOut])
def get_audit(
    limit: int = Query(default=500, ge=1, le=10000),
    action: str | None = Query(default=None, description="filter to one action value, e.g. soft_decline"),
    log_path: str = Query(default=DEFAULT_LOG_PATH),
) -> list[dict]:
    """Return audit log records, most recent first."""
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"No audit log at {log_path} yet -- run `python -m cli.main` first")

    if action is not None:
        records = [r for r in records if r["action"] == action]
    records.reverse()
    return records[:limit]


@app.get("/metrics", response_model=MetricsOut)
def get_metrics(
    dataset_path: str = Query(default=HELDOUT_PATH),
    fp_cost: float = Query(default=650.0, description="INR cost of one false positive"),
    fn_cost: float = Query(default=5000.0, description="INR cost of one false negative"),
) -> MetricsOut:
    """Run the eval fresh against `dataset_path` and return
    precision/recall/FP-rate/$-cost. Cheap enough at this project's scale
    (a few thousand events) to compute on every request rather than cache.
    """
    try:
        result = run_eval(dataset_path, fp_cost, fn_cost)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail=f"No dataset at {dataset_path} -- run `python -m data.generate_synthetic` first"
        )

    return MetricsOut(
        dataset_path=dataset_path,
        n_actors=result["n_actors"],
        confusion_matrix=ConfusionMatrixOut(**result["metrics"]),
        cost=CostBreakdownOut(**result["cost"]),
        computed_at=datetime.now(timezone.utc).isoformat(),
    )


# Mounted last and at "/" so it only catches paths /audit, /metrics, /health,
# /docs, and /openapi.json didn't already claim.
if os.path.isdir(_WEB_DIR):
    app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")
