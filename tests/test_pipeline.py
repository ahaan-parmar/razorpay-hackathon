"""Unit test for detection/pipeline.py's empty-actor_events guard."""

import pytest

from detection.pipeline import evaluate_actor


def test_evaluate_actor_rejects_empty_events():
    with pytest.raises(ValueError):
        evaluate_actor([], reference_events=[])
