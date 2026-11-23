"""
test_cwe_mapping.py — Authoritative CWE Mapping, Taxonomy & Regression Tests.

Validates:
  - Exact 15-class MITRE taxonomy order (Phase 2 alignment).
  - SQL Injection (CWE-89) resolution vs historical CWE-362 false classification.
  - Confidence thresholding & uncertainty flags.
  - Granular vulnerability category resolution.
"""

import pytest
from src.data.cwe_taxonomy import (
    CWE_SEMANTIC_GROUPS,
    CLASS_NAMES,
    CLASS_TO_IDX,
    CWE_TO_GROUP,
    CWE_METADATA,
    resolve_cwe_prediction,
)
from tests.fixtures.catalog import TEST_CASES


def test_taxonomy_15_classes():
    """Verify exactly 15 classes exist in strict deterministic training order."""
    assert len(CLASS_NAMES) == 15
    assert CLASS_NAMES[0] == "Buffer-Overflow"
    assert CLASS_NAMES[7] == "Input-Validation"
    assert CLASS_NAMES[12] == "Race-Condition"
    assert CLASS_NAMES[14] == "Other-Security"

    for idx, name in enumerate(CLASS_NAMES):
        assert CLASS_TO_IDX[name] == idx


def test_cwe89_in_input_validation():
    """Ensure CWE-89 is correctly categorized under Input-Validation in training taxonomy."""
    assert "CWE-89" in CWE_SEMANTIC_GROUPS["Input-Validation"]
    assert CWE_TO_GROUP.get("CWE-89") == "Input-Validation"


def test_sql_injection_regression_resolution():
    """
    CRITICAL REGRESSION TEST:
    Verifies that Python SQL injection is resolved as CWE-89 / Input-Validation,
    NOT misclassified as CWE-362 (Race Condition) or generic CWE-20.
    """
    sql_code = """import sqlite3

def authenticate_user(conn, username, password):
    cursor = conn.cursor()
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    # Simulate cross-tier neural noise where C model output has low confidence
    noisy_probs = [0.06] * 15
    noisy_probs[12] = 0.08  # Historical bug: class 12 (Race-Condition) barely edged out

    res = resolve_cwe_prediction(12, noisy_probs, sql_code, "Python")

    assert res["cwe_id"] == "CWE-89", f"Expected CWE-89, got {res['cwe_id']}"
    assert res["semantic_group"] == "Input-Validation"
    assert res["vulnerability_name"] == "SQL Injection"
    assert res["category"] == "Injection"
    assert res["status"] == "corroborated"
    assert res["is_confident"] is True


def test_noise_yields_uncertain():
    """Ensure that arbitrary code with low confidence and no evidence is flagged 'Uncertain'."""
    noisy_probs = [0.066] * 15  # Uniform noise (1/15)
    code = "def sample(): return 42"

    res = resolve_cwe_prediction(0, noisy_probs, code, "Python", confidence_threshold=0.25)
    assert res["cwe_id"] == "Uncertain"
    assert res["is_confident"] is False
    assert res["status"] == "uncertain"
    assert "Review Recommended" in res["display"]


def test_high_confidence_neural_preserved():
    """Ensure confident neural predictions without conflicting evidence are preserved."""
    confident_probs = [0.01] * 15
    confident_probs[0] = 0.85  # Buffer-Overflow confident

    c_code = "void overflow(char *s) { char buf[10]; memcpy(buf, s, 100); }"
    res = resolve_cwe_prediction(0, confident_probs, c_code, "C", confidence_threshold=0.25)

    assert res["semantic_group"] == "Buffer-Overflow"
    assert res["is_confident"] is True
    assert res["confidence"] >= 0.85


def test_all_catalog_vulnerable_cases():
    """Verify taxonomy resolves all 25 vulnerable catalog cases to valid CWEs."""
    vuln_cases = [tc for tc in TEST_CASES if tc["expected_vf"]]
    assert len(vuln_cases) == 25

    for tc in vuln_cases:
        expected_cwe = tc["expected_cwe"]
        expected_group = tc["expected_semantic_group"]

        # Synthetic test run through resolver
        res = resolve_cwe_prediction(None, None, tc["code"], tc["language"])
        assert res["cwe_id"] != "CWE-Unknown"
        assert res["semantic_group"] in CLASS_NAMES

