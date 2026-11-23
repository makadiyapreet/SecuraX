"""
test_severity.py — Unit & Integration Tests for Severity Scoring (Phase 3 CVSS 0-10).

Tests:
  - Band mappings (Low, Medium, High, Critical).
  - Normalization and score clipping [0.0 - 10.0].
  - Model estimate disclaimers.
  - Safe code N/A handling.
"""

import pytest
from src.pipeline.model_manager import LocalModelManager, get_cvss_band


def test_cvss_band_mapping():
    """Verify standard CVSS severity band thresholds."""
    assert get_cvss_band(0.0) == "Low"
    assert get_cvss_band(3.9) == "Low"
    assert get_cvss_band(4.0) == "Medium"
    assert get_cvss_band(6.9) == "Medium"
    assert get_cvss_band(7.0) == "High"
    assert get_cvss_band(8.9) == "High"
    assert get_cvss_band(9.0) == "Critical"
    assert get_cvss_band(10.0) == "Critical"


def test_severity_prediction_fallback():
    """Verify fallback severity estimation structure and disclaimer notice."""
    mm = LocalModelManager(device="cpu")
    orig_tok = mm.tokenizer
    mm.tokenizer = None  # Force fallback

    res = mm.predict_severity("int main() { return 0; }", "tier1_c_cpp")
    assert 0.0 <= res["severity_score"] <= 10.0
    assert res["band"] in ("Low", "Medium", "High", "Critical")
    assert res.get("is_estimate") is True
    assert "not an official CVSS assessment" in res.get("notice", "")

    mm.tokenizer = orig_tok


@pytest.mark.integration
def test_neural_severity_prediction():
    """Integration test: real neural severity scoring for Python."""
    mm = LocalModelManager()
    model = mm._get_phase3_model("tier2_python")
    if model is None:
        pytest.skip("Phase 3 tier2_python checkpoint not found")

    code = "import sqlite3\ncursor.execute(f'SELECT * FROM x WHERE y={z}')"
    res = mm.predict_severity(code, "tier2_python")

    assert "severity_score" in res
    assert 0.0 <= res["severity_score"] <= 10.0
    assert res["band"] in ("Low", "Medium", "High", "Critical")
    assert res.get("is_estimate") is True

