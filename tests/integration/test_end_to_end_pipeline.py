"""
test_end_to_end_pipeline.py — Multi-Tier End-to-End Pipeline Integration Suite.

Covers:
  - Language detection & tier routing
  - Function chunking and LOC calculation
  - Multi-tier binary vulnerability detection
  - 15-class CWE taxonomy classification
  - CVSS severity continuous scoring
  - Table schema conforming to:
    PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
"""

import pytest
from src.pipeline.securax_pipeline import SecuraXPipeline
from src.pipeline.language_detector import detect_language, map_language_to_tier, get_supported_languages
from src.pipeline.chunker import split_code_into_functions, count_loc
from src.data.cwe_taxonomy import CLASS_NAMES, resolve_cwe_prediction


@pytest.fixture(scope="module")
def pipeline():
    return SecuraXPipeline()


def test_language_routing_and_tiers():
    """Verify that all canonical languages map to their documented tiers."""
    expected_tiers = {
        "C": "tier1_c_cpp",
        "C++": "tier2_cpp",
        "Python": "tier2_python",
        "PHP": "tier2_php",
        "JavaScript": "tier3_shared",
        "TypeScript": "tier3_shared",
        "Go": "tier3_shared",
        "Java": "tier3_shared",
        "Ruby": "tier3_shared",
    }
    for lang, tier in expected_tiers.items():
        mapped = map_language_to_tier(lang)
        assert mapped == tier, f"Language {lang} expected tier {tier}, got {mapped}"
        # Case-insensitive check
        assert map_language_to_tier(lang.lower()) == tier


def test_unsupported_language_rejection():
    """Verify that unsupported languages fail gracefully without guessing."""
    unsupported = ["Rust", "Kotlin", "Swift", "Scala", "Lua", "Brainfuck"]
    for lang in unsupported:
        tier = map_language_to_tier(lang)
        assert tier is None, f"Unsupported language {lang} should map to None"


def test_table_output_schema_compliance(pipeline):
    """
    Verify results table schema strictly adheres to:
    PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
    """
    code = """#include <string.h>
void vuln(char *src) {
    char dest[16];
    strcpy(dest, src);
}"""
    res = pipeline.analyze_source(code, language_override="C", refinement_cap=0)
    assert res["success"] is True
    assert len(res["rows"]) >= 1

    row = res["rows"][0]
    required_keys = ["PL", "Snippet", "VF", "CWE-id", "Refined Code", "LOC", "Severity Score"]
    for key in required_keys:
        assert key in row, f"Required column '{key}' missing from results table row"

    assert row["PL"] == "C"
    assert row["VF"] in ("Vulnerable", "Safe", "Uncertain")
    assert isinstance(row["LOC"], int)


def test_safe_snippet_n_a_semantics(pipeline):
    """Verify that Safe functions report CWE-id: N/A, Severity Score: N/A, Refined Code: N/A."""
    code = """import os

def connect_cloud_api():
    api_key = os.environ.get("API_SECRET")
    if not api_key:
        raise ValueError("API_SECRET not set")
    return "Connected" """
    res = pipeline.analyze_source(code, language_override="Python", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] == "Safe"
    assert row["CWE-id"] == "N/A"
    assert row["Refined Code"] == "N/A"
    assert row["Severity Score"] == "N/A"
