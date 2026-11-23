"""
test_refinement.py — Unit & Integration Tests for Code Refinement (Phase 4).

Tests:
  - Prompt construction with language and CWE context.
  - Markdown code block extraction.
  - Multi-case response parsing.
  - Syntax check integration.
"""

import pytest
from src.refinement.prompts import (
    build_refinement_prompt,
    parse_refinement_response,
)
from src.evaluation.evaluate_repair import check_syntax


def test_build_refinement_prompt():
    """Verify prompt formatting contains language, CWE ID, and snippet."""
    prompt = build_refinement_prompt(
        language="Python",
        vulnerable_snippet="cursor.execute('SELECT ' + u)",
        cwe_id="CWE-89",
        semantic_group="Input-Validation",
        severity_score=8.5,
    )
    assert "Python" in prompt
    assert "CWE-89" in prompt
    assert "Input-Validation" in prompt
    assert "cursor.execute" in prompt
    assert "8.5" in prompt


def test_parse_refinement_response():
    """Verify markdown code block extraction."""
    # Standard fenced code block
    raw = "Here is the fixed code:\n```python\ndef secure():\n    return True\n```\nExplanation..."
    parsed = parse_refinement_response(raw, "Python")
    assert parsed["status"] == "success"
    code_text = parsed.get("refined_code") or parsed.get("code") or ""
    assert "def secure():" in code_text

    # Raw code without fences
    raw_no_fences = "def secure():\n    return True"
    parsed_no_fences = parse_refinement_response(raw_no_fences, "Python")
    assert parsed_no_fences["status"] == "raw_code_no_fences"
    no_fences_code = parsed_no_fences.get("refined_code") or parsed_no_fences.get("code") or ""
    assert "def secure():" in no_fences_code


def test_syntax_checker():
    """Verify syntax checks across Python and C."""
    valid_py = "def f(x):\n    return x + 1"
    invalid_py = "def f(x:\n    return x"
    assert check_syntax(valid_py, "Python") is True
    assert check_syntax(invalid_py, "Python") is False

    valid_c = "int main(void) { return 0; }"
    invalid_c = "int main(void) { return 0;"  # Unclosed brace
    assert check_syntax(valid_c, "C") is True
    assert check_syntax(invalid_c, "C") is False
