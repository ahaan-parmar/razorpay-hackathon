"""Stable, typed response shapes for export/server.py.

These are the actual contract a separately-built frontend codes
against -- kept deliberately flat and JSON-primitive (no enums, no
nested project types) so a frontend never needs to import anything
from this repo. FastAPI derives the OpenAPI schema (http://host/docs)
directly from these models, so this file and the live docs can't drift
apart from each other -- only from the audit log's actual shape if
audit/logger.py's record dict ever changes without updating this file
too.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


class AuditRecordOut(BaseModel):
    logged_at: str
    event_id: str
    event_timestamp: str
    actor: str
    source: str
    rules_fired: list[str]
    rule_evidence: dict[str, dict[str, Any]]
    confidence: float
    action: str
    dry_run: bool
    rationale: str
    explanation: Optional[str] = None


class ConfusionMatrixOut(BaseModel):
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    fp_rate: float


class CostBreakdownOut(BaseModel):
    fp_count: int
    fn_count: int
    fp_unit_cost: float
    fn_unit_cost: float
    total_fp_cost: float
    total_fn_cost: float
    total_cost: float


class MetricsOut(BaseModel):
    dataset_path: str
    n_actors: int
    confusion_matrix: ConfusionMatrixOut
    cost: CostBreakdownOut
    computed_at: str
