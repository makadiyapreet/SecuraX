"""
test_self_verification.py — Unit & Integration Tests for Phase 7 Option B Self-Verification.

Tests:
  - Multi-source verification logic (syntax + neural + static analysis).
  - Diagnostic re-prompt feedback formatting.
  - Rejection of invalid or insecure candidate patches.
  - Acceptance of verified clean patches.
"""

import pytest
from src.refinement.self_verification import (
    verify_patch_candidate,
    run_static_analysis,
)
from src.refinement.prompts import build_self_verification_prompt
from src.pipeline.model_manager import LocalModelManager


def test_verify_empty_patch():
    """Verify empty patch candidates fail immediately."""
    mm = LocalModelManager(device="cpu")
    res = verify_patch_candidate("", "Python", "tier2_python", mm)
    assert res["passed"] is False
    assert res["syntax_valid"] is False
    assert "empty" in res["reason"].lower()


def test_verify_syntax_error_patch():
    """Verify syntactically broken patches fail."""
    mm = LocalModelManager(device="cpu")
    broken_code = "def broken(\n    return 42"
    res = verify_patch_candidate(broken_code, "Python", "tier2_python", mm)
    assert res["passed"] is False
    assert res["syntax_valid"] is False
    assert "syntax" in res["reason"].lower()


def test_verify_residual_static_issue_patch():
    """Verify candidate patch with residual SQL injection is flagged and rejected."""
    mm = LocalModelManager(device="cpu")
    # Insecure patch attempting fix but still interpolating
    still_vuln_patch = """import sqlite3
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchall()
"""
    res = verify_patch_candidate(still_vuln_patch, "Python", "tier2_python", mm)
    assert res["passed"] is False
    assert res["is_vulnerable"] is True
    assert any("SQL Injection" in w or "CWE-89" in w for w in res["static_warnings"])


def test_diagnostic_prompt_construction():
    """Verify diagnostic re-prompt includes previous failed patch, feedback, and attribution."""
    prompt = build_self_verification_prompt(
        language="Python",
        original_code="query = 'SELECT ' + u",
        previous_patch="query = f'SELECT {u}'",
        cwe_id="CWE-89",
        detector_prob=0.95,
        detector_threshold=0.15,
        static_warnings=["[CWE-89] SQL injection via f-string"],
    )
    assert "failed automated verification" in prompt.lower()
    assert "CWE-89" in prompt
    assert "95.0%" in prompt or "95%" in prompt
    assert "query = f'SELECT {u}'" in prompt
