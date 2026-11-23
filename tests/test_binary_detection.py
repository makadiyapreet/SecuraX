"""
test_binary_detection.py — Unit & Integration Tests for Binary Vulnerability Detection (Phase 1).

Tests:
  - Per-tier optimal threshold loading from Phase 1 ROC/PR analysis.
  - Model manager initialization on device (CPU/MPS).
  - Mode A (heuristic & structural tests).
  - Mode B (full neural inference when checkpoints are available).
"""

import pytest
import torch
from src.pipeline.model_manager import LocalModelManager, PHASE1_THRESHOLDS


def test_phase1_thresholds():
    """Verify each language tier has its calibrated optimal threshold."""
    assert PHASE1_THRESHOLDS["tier1_c_cpp"] == 0.70
    assert PHASE1_THRESHOLDS["tier2_cpp"] == 0.10
    assert PHASE1_THRESHOLDS["tier2_python"] == 0.15
    assert PHASE1_THRESHOLDS["tier2_php"] == 0.10
    assert PHASE1_THRESHOLDS["tier3_shared"] == 0.50


def test_model_manager_init():
    """Verify LocalModelManager initializes device and tokenizer without error."""
    mm = LocalModelManager(device="cpu")
    assert mm.device == torch.device("cpu")
    assert mm.tokenizer is not None


def test_binary_vf_fallback():
    """Verify heuristic fallback functions correctly when models are unavailable."""
    mm = LocalModelManager(device="cpu")
    # Force tokenizer to None to test pure fallback behavior
    orig_tok = mm.tokenizer
    mm.tokenizer = None

    vuln_code = "void copy(char *s) { char b[10]; strcpy(b, s); }"
    res_vuln = mm.predict_binary_vf(vuln_code, "tier1_c_cpp", return_explainability=False)
    assert res_vuln["is_vulnerable"] is True
    assert res_vuln["prob_vuln"] >= 0.70
    assert res_vuln["mode"] == "heuristic_fallback"

    safe_code = "int add(int a, int b) { return a + b; }"
    res_safe = mm.predict_binary_vf(safe_code, "tier1_c_cpp", return_explainability=False)
    assert res_safe["is_vulnerable"] is False
    assert res_safe["prob_vuln"] < 0.70

    # Restore tokenizer
    mm.tokenizer = orig_tok


@pytest.mark.integration
def test_neural_binary_inference_tier2_python():
    """Integration test: real neural model prediction for Python tier."""
    mm = LocalModelManager()
    model = mm._get_phase1_model("tier2_python")
    if model is None:
        pytest.skip("Phase 1 tier2_python checkpoint not found")

    sql_code = """import sqlite3
def get_user(username):
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
"""
    res = mm.predict_binary_vf(sql_code, "tier2_python")
    assert res["is_vulnerable"] is True
    assert res["prob_vuln"] >= 0.15
    assert res["threshold"] == 0.15
    assert res["mode"] == "neural"

