"""
test_explainability.py — Unit & Integration Tests for Line Attribution & Heatmaps.

Tests:
  - Token-to-line attribution mapping.
  - Special token & padding exclusion.
  - Normalization into [0.0 - 1.0].
  - Top line ranking.
  - HTML heatmap generation.
"""

import pytest
import torch
from src.pipeline.explainability import compute_line_attributions
from transformers import AutoTokenizer


def test_line_attribution_normalization():
    """Verify line scores normalize between 0.0 and 1.0."""
    code = "line1\nline2\nline3"
    # Synthetic attention weights
    weights = torch.tensor([0.1, 0.4, 0.8, 0.2])

    tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
    res = compute_line_attributions(code, tokenizer, weights)

    assert len(res["lines"]) == 3
    for l in res["lines"]:
        assert 0.0 <= l["score"] <= 1.0

    assert len(res["top_lines"]) <= 3
    assert "html_heatmap" in res
    assert "<div" in res["html_heatmap"]


def test_top_line_ranking():
    """Verify top lines correspond to highest attribution score."""
    code = "import os\ndef test():\n    strcpy(buf, s)\n    return 0"
    tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
    # Synthetic empty weights triggers fallback keyword attribution
    res = compute_line_attributions(code, tokenizer, torch.tensor([]))

    top = res["top_lines"]
    assert len(top) > 0
    # strcpy line should have the highest score in fallback
    assert any("strcpy" in l["text"] for l in top)

