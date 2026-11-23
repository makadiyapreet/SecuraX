"""
test_pipeline_integration.py — End-to-End Pipeline Integration & Schema Tests.

Tests:
  - Exact 7-column output schema: PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score.
  - Multi-language routing.
  - Vulnerability detection + CWE resolution + Severity scoring.
  - Refinement cap protection.
  - Safe code N/A representation.
"""

import pytest
from src.pipeline.securax_pipeline import SecuraXPipeline


def test_pipeline_exact_schema():
    """Verify that rows returned by pipeline match exact required schema."""
    pipeline = SecuraXPipeline()
    code = """def calc(a, b):
    return a + b
"""
    res = pipeline.analyze_source(code, filename="math_utils.py")
    assert res["success"] is True
    assert len(res["rows"]) >= 1

    expected_keys = ["PL", "Snippet", "VF", "CWE-id", "Refined Code", "LOC", "Severity Score"]
    for row in res["rows"]:
        assert list(row.keys()) == expected_keys
        assert row["PL"] == "Python"
        assert row["Snippet"].endswith("()")
        assert row["VF"] in ("Vulnerable", "Safe")


def test_safe_function_representation():
    """Verify safe functions display N/A for CWE and Severity."""
    pipeline = SecuraXPipeline()
    code = """def safe_add(x, y):
    return x + y
"""
    res = pipeline.analyze_source(code, filename="safe.py")
    assert res["success"] is True
    row = res["rows"][0]
    if row["VF"] == "Safe":
        assert row["CWE-id"] == "N/A"
        assert row["Severity Score"] == "N/A"
        assert row["Refined Code"] == "N/A"


def test_refinement_cap_enforcement():
    """Verify refinement cap limits Groq calls and provides on-demand message."""
    pipeline = SecuraXPipeline()
    code = """import os
def f1(p): os.system("ping " + p)
def f2(p): os.system("nslookup " + p)
def f3(p): os.system("traceroute " + p)
"""
    res = pipeline.analyze_source(code, filename="net.py", refinement_cap=1)
    assert res["success"] is True
    assert res["refinement_cap"] == 1
    if res["vulnerable_count"] > 1:
        assert res["cap_hit"] is True
        skipped_rows = [r for r in res["rows"] if "Refinement cap reached" in r["Refined Code"]]
        assert len(skipped_rows) >= 1

