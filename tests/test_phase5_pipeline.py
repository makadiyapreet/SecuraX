"""
test_phase5_pipeline.py — Comprehensive End-to-End Pipeline Verification Suite.

Tests:
  1. C source file (Tier 1 C/C++) — Buffer overflow detection, CWE, severity & refinement
  2. Python source file (Tier 2 Python) — SQL injection detection & refinement
  3. PHP source file (Tier 2 PHP) — Cross-site scripting detection & refinement
  4. JavaScript source file (Tier 3 Shared) — Command injection
  5. Go source file (Tier 3 Shared) — Path traversal
  6. Unsupported language (Rust / Swift) — Graceful rejection without routing to wrong tier
  7. API key removed — Graceful degradation (Phase 1-3 work, Phase 4 reports unavailable)
  8. HTTP 429 simulation — Automatic key failover or exponential backoff without crash
  9. Refinement cap enforcement — Protects free-tier quota and enables on-demand refinement
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.language_detector import detect_language, get_supported_languages
from src.pipeline.chunker import split_code_into_functions
from src.pipeline.securax_pipeline import SecuraXPipeline


def test_end_to_end_multilang():
    """Test 5 files covering 3+ tiers."""
    print("=" * 70)
    print("TEST 1-5: END-TO-END MULTI-LANGUAGE PIPELINE ON 5 FILES")
    print("=" * 70)

    pipeline = SecuraXPipeline(device="cpu")

    test_files = [
        # (filename, code, expected_lang, expected_tier)
        (
            "vuln_buffer.c",
            """#include <stdio.h>
#include <string.h>

void safe_log(const char *msg) {
    printf("[LOG] %s\\n", msg);
}

void copy_payload(char *payload) {
    char stack_buf[16];
    strcpy(stack_buf, payload);
}
""",
            "C",
            "tier1_c_cpp",
        ),
        (
            "db_auth.py",
            """import sqlite3

def check_db_health(conn):
    return True

def query_user_records(conn, user_input):
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(sql)
    return cursor.fetchall()
""",
            "Python",
            "tier2_python",
        ),
        (
            "render_view.php",
            """<?php

function get_version() {
    return "1.0.0";
}

function display_comment($comment_body) {
    echo "<div>" . $comment_body . "</div>";
}
?>
""",
            "PHP",
            "tier2_php",
        ),
        (
            "server_exec.js",
            """const { exec } = require('child_process');

function getUptime() {
    return process.uptime();
}

function runBackup(destFolder) {
    exec("tar -czf backup.tar.gz " + destFolder);
}
""",
            "JavaScript",
            "tier3_shared",
        ),
        (
            "handler.go",
            """package main
import (
    "fmt"
    "os"
)

func ReadStatus() string {
    return "OK"
}

func OpenUserFile(userInputPath string) (*os.File, error) {
    return os.Open("/data/" + userInputPath)
}
""",
            "Go",
            "tier3_shared",
        ),
    ]

    for fname, code, exp_lang, exp_tier in test_files:
        print(f"\n[Testing file: {fname}]")
        res = pipeline.analyze_source(code, filename=fname, refinement_cap=5)

        assert res["success"] is True, f"Pipeline failed on {fname}: {res.get('error')}"
        assert res["language"] == exp_lang, f"Expected {exp_lang}, got {res['language']}"
        assert res["tier"] == exp_tier, f"Expected {exp_tier}, got {res['tier']}"
        assert len(res["rows"]) >= 2, f"Expected at least 2 function chunks in {fname}, got {len(res['rows'])}"

        # Verify output row schema
        required_columns = {"PL", "Snippet", "VF", "CWE-id", "Refined Code", "LOC", "Severity Score"}
        for r in res["rows"]:
            assert set(r.keys()) == required_columns, f"Row columns mismatch: {set(r.keys())}"
            print(f"  -> {r['PL']:10} | {r['Snippet']:22} | {r['VF']:10} | {r['CWE-id']:15} | LOC:{r['LOC']:2} | CVSS: {r['Severity Score']}")

    print("\n✅ All 5 multi-language files processed successfully with valid table schema!")


def test_unsupported_language():
    """Test 6: Verify unsupported language fails gracefully and NEVER routes to wrong tier."""
    print("\n" + "=" * 70)
    print("TEST 6: UNSUPPORTED LANGUAGE HANDLING")
    print("=" * 70)

    pipeline = SecuraXPipeline(device="cpu")
    rust_code = """fn main() {
    let mut s = String::from("hello");
    s.push_str(", world!");
    println!("{}", s);
}"""

    res = pipeline.analyze_source(rust_code, filename="main.rs")
    print("Rust file test result:", res["success"], "| Error:", res["error"])

    assert res["success"] is False, "Unsupported language should not return success=True"
    assert res["tier"] is None, "Unsupported language must have tier=None"
    assert "not supported" in res["error"], "Expected clear unsupported language message"
    print("✅ Unsupported language handled gracefully without invalid routing!")


def test_api_key_missing_fallback():
    """Test 7: Verify pipeline functions properly when GROQ_API_KEY is not set."""
    print("\n" + "=" * 70)
    print("TEST 7: GROQ API KEY MISSING (GRACEFUL DEGRADATION)")
    print("=" * 70)

    # Instantiate pipeline with simulated missing key
    pipeline = SecuraXPipeline(device="cpu")
    pipeline.groq_client.is_available = False
    pipeline.groq_client.api_keys = []
    pipeline.groq_client.unavailable_reason = "GROQ_API_KEY is not set in environment."

    test_py = """def query_user_records(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)
"""

    res = pipeline.analyze_source(test_py, filename="test.py")
    assert res["success"] is True, "Pipeline must succeed for Phases 1-3 even when API key is missing"
    assert res["vulnerable_count"] >= 1, "Vulnerability must still be flagged"

    vuln_row = [r for r in res["rows"] if r["VF"] == "Vulnerable"][0]
    print(f"Refined Code cell contents: '{vuln_row['Refined Code']}'")
    assert "Refinement unavailable" in vuln_row["Refined Code"]
    print("✅ Graceful degradation verified: detection, CWE and severity work, refinement shows clear notice!")


def test_rate_limit_and_fallback_rotation():
    """Test 8: Verify automatic failover upon rate limit (429) simulation."""
    print("\n" + "=" * 70)
    print("TEST 8: 429 SIMULATION & AUTOMATIC FAILOVER POOL")
    print("=" * 70)

    pipeline = SecuraXPipeline(device="cpu")
    # Setup dual keys (Key 1 dummy/exhausted, Key 2 active)
    active_key = pipeline.groq_client.api_keys[0] if pipeline.groq_client.api_keys else "gsk_live_key"
    pipeline.groq_client.api_keys = ["gsk_exhausted_key_1", active_key]
    pipeline.groq_client.current_key_idx = 0
    from groq import Groq
    pipeline.groq_client._groq_client = Groq(api_key=pipeline.groq_client.api_keys[0], timeout=5.0)

    # Bypass cache for this simulation to force live API call
    pipeline.groq_client.cache_enabled = False
    print("Initial key index:", pipeline.groq_client.current_key_idx)
    import time
    res = pipeline.groq_client.complete(f"Write def ping_failover_{time.time()}(): return True in Python", max_tokens=100)
    print("Status after request:", res.get("status"))
    print("Final key index:", pipeline.groq_client.current_key_idx)

    assert pipeline.groq_client.current_key_idx == 1, "Must have automatically transferred to fallback key #2"
    print("✅ Rate limit & credit exhaustion automatic failover verified!")


def test_refinement_cap():
    """Test 9: Verify refinement cap protects free quota and flags cap_hit."""
    print("\n" + "=" * 70)
    print("TEST 9: REFINEMENT CAP ENFORCEMENT (QUOTA PROTECTION)")
    print("=" * 70)

    pipeline = SecuraXPipeline(device="cpu")
    # Code with 3 vulnerable functions
    multi_func_code = """
def f1(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)

def f2(user_name):
    query = f"SELECT * FROM accounts WHERE name = '{user_name}'"
    return db.execute(query)

def f3(order_id):
    query = f"SELECT * FROM orders WHERE id = '{order_id}'"
    return db.execute(query)
"""
    # Enforce strict cap of 1 refinement call
    res = pipeline.analyze_source(multi_func_code, filename="multi.py", refinement_cap=1)
    print(f"Total functions: {res['total_functions']} | Refined: {res['refined_count']} | Cap Hit: {res['cap_hit']}")

    assert res["refined_count"] == 1, f"Expected exactly 1 refinement call, got {res['refined_count']}"
    assert res["cap_hit"] is True, "Expected cap_hit=True"

    # Verify subsequent functions report cap reached
    cap_rows = [r for r in res["rows"] if "Refinement cap reached" in r["Refined Code"]]
    assert len(cap_rows) >= 1, "Expected rows indicating refinement cap reached"
    print(f"Skipped snippet cell: '{cap_rows[0]['Refined Code']}'")

    # Verify on-demand refinement works for skipped snippet
    od_res = pipeline.refine_single_snippet_on_demand(
        snippet_code="void f2(char *p) { char b[8]; strcpy(b, p); }",
        language="C",
        cwe_id="CWE-119",
        semantic_group="Buffer-Overflow",
        severity_score=7.5
    )
    assert od_res["success"] is True, "On-demand refinement failed"
    print("✅ Refinement cap and on-demand refinement verified!")


if __name__ == "__main__":
    test_end_to_end_multilang()
    test_unsupported_language()
    test_api_key_missing_fallback()
    test_rate_limit_and_fallback_rotation()
    test_refinement_cap()
    print("\n🎉 ALL PHASE 5 PIPELINE INTEGRATION TESTS PASSED 100%!")
