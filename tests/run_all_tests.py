"""
run_all_tests.py — Automated Test Runner & Results Exporter for SecuraX.

Executes:
  - Mode A: Lightweight unit & regression tests across all 50 fixtures.
  - Mode B: Full neural model & pipeline integration tests.
  - Exports consolidated JSON report to results/SECURAX_REGRESSION_TEST_RESULTS.json.

Usage:
    python tests/run_all_tests.py [--mode lightweight|full]
"""

import sys
import time
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.catalog import TEST_CASES
from src.pipeline.language_detector import detect_language, map_language_to_tier
from src.pipeline.chunker import split_code_into_functions
from src.data.cwe_taxonomy import resolve_cwe_prediction
from src.evaluation.evaluate_repair import check_syntax
from src.refinement.static_security import run_comprehensive_static_analysis
from src.pipeline.model_manager import LocalModelManager, get_cvss_band


def run_catalog_benchmarks(mode: str = "lightweight") -> dict:
    """Evaluate all 50 catalog test cases against SecuraX modules."""
    print("=" * 80)
    print(f"SECURAX COMPREHENSIVE TEST SUITE — {len(TEST_CASES)} CASES [Mode: {mode.upper()}]")
    print("=" * 80)

    results = []
    category_summary = {}
    lang_summary = {}

    v_correct = 0
    s_correct = 0
    cwe_correct = 0
    syntax_passed = 0

    mm = None
    if mode == "full":
        try:
            mm = LocalModelManager()
            print("Loaded LocalModelManager for full integration testing.")
        except Exception as e:
            print(f"Warning: Could not initialize LocalModelManager ({e}), falling back to lightweight mode.")

    for tc in TEST_CASES:
        t_id = tc["id"]
        lang = tc["language"]
        code = tc["code"]
        exp_vf = tc["expected_vf"]
        exp_cwe = tc["expected_cwe"]
        exp_group = tc["expected_semantic_group"]
        cat = tc["category"]

        # 1. Language detection
        det_lang, det_tier, supported, _ = detect_language(code)
        lang_match = (det_lang.lower() == lang.lower())

        # 2. Function extraction
        chunks = split_code_into_functions(code, lang)
        has_chunk = len(chunks) >= 1

        # 3. Syntax validity
        is_syntax_valid = check_syntax(code, lang)
        if is_syntax_valid:
            syntax_passed += 1

        # 4. Static / Semantic analysis
        static_res = run_comprehensive_static_analysis(code, lang)
        static_detected_vuln = not static_res["clean"]

        # 5. CWE resolution
        cwe_res = resolve_cwe_prediction(None, None, code, lang)
        pred_cwe = cwe_res["cwe_id"]
        pred_group = cwe_res["semantic_group"]

        # Determine detection verdict
        if mode == "full" and mm is not None:
            tier = tc.get("tier") or map_language_to_tier(lang) or "tier1_c_cpp"
            p1 = mm.predict_binary_vf(code, tier, return_explainability=False)
            pred_vf = p1["is_vulnerable"]
        else:
            # Lightweight mode: combination of static & signature analysis
            pred_vf = static_detected_vuln or (cwe_res["cwe_id"] not in ("N/A", "Uncertain"))

        # Scoring
        if exp_vf:
            vf_match = (pred_vf == True)
            if vf_match:
                v_correct += 1
            # CWE match: either exact CWE match or correct semantic group
            cwe_match = (pred_cwe == exp_cwe) or (pred_group == exp_group)
            if cwe_match:
                cwe_correct += 1
        else:
            # Safe snippet: should NOT be marked vulnerable by static analysis
            vf_match = (static_detected_vuln == False)
            if vf_match:
                s_correct += 1
            cwe_match = True  # Safe snippets have N/A

        status_mark = "PASS" if (vf_match and (not exp_vf or cwe_match)) else "WARN"

        res_entry = {
            "id": t_id,
            "category": cat,
            "language": lang,
            "expected_vf": exp_vf,
            "predicted_vf": pred_vf,
            "vf_match": vf_match,
            "expected_cwe": exp_cwe,
            "predicted_cwe": pred_cwe,
            "predicted_group": pred_group,
            "cwe_match": cwe_match,
            "syntax_valid": is_syntax_valid,
            "status": status_mark,
        }
        results.append(res_entry)

        # Summaries
        lang_summary[lang] = lang_summary.get(lang, 0) + (1 if status_mark == "PASS" else 0)
        category_summary[cat] = category_summary.get(cat, 0) + (1 if status_mark == "PASS" else 0)

        print(f"[{t_id}] {lang:10s} | {cat:28s} | Expected VF: {str(exp_vf):5s} | Pred: {str(pred_vf):5s} | CWE: {pred_cwe:8s} | {status_mark}")

    total_vuln = sum(1 for tc in TEST_CASES if tc["expected_vf"])
    total_safe = sum(1 for tc in TEST_CASES if not tc["expected_vf"])
    total_cases = len(TEST_CASES)
    total_passed = sum(1 for r in results if r["status"] == "PASS")

    print("\n" + "=" * 80)
    print("CONSOLIDATED BENCHMARK SUMMARY")
    print("=" * 80)
    print(f"Total Test Cases      : {total_cases}")
    print(f"Total Passing         : {total_passed} / {total_cases} ({total_passed/total_cases:.1%})")
    print(f"Vulnerable Recall     : {v_correct} / {total_vuln} ({v_correct/total_vuln:.1%})")
    print(f"Safe Specificity      : {s_correct} / {total_safe} ({s_correct/total_safe:.1%})")
    print(f"CWE Group Accuracy    : {cwe_correct} / {total_vuln} ({cwe_correct/total_vuln:.1%})")
    print(f"Syntax Validity Rate  : {syntax_passed} / {total_cases} ({syntax_passed/total_cases:.1%})")
    print("=" * 80)

    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": mode,
        "total_test_cases": total_cases,
        "total_passed": total_passed,
        "pass_rate": round(total_passed / total_cases, 4),
        "vulnerable_recall": round(v_correct / total_vuln, 4),
        "safe_specificity": round(s_correct / total_safe, 4),
        "cwe_group_accuracy": round(cwe_correct / total_vuln, 4),
        "syntax_validity_rate": round(syntax_passed / total_cases, 4),
        "results": results,
    }

    # Save to results/
    out_file = PROJECT_ROOT / "results" / "SECURAX_REGRESSION_TEST_RESULTS.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"Saved results to: {out_file.relative_to(PROJECT_ROOT)}")
    return summary_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["lightweight", "full"], default="lightweight")
    args = parser.parse_args()

    data = run_catalog_benchmarks(mode=args.mode)
    if data["pass_rate"] >= 0.80:
        sys.exit(0)
    else:
        sys.exit(1)

