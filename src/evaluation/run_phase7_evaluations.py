"""
run_phase7_evaluations.py — Phase 7: Stretch Goal Evaluation Benchmarks.

Evaluates:
  Option B — Self-Verification Loop:
    - Pass 1 vs Pass 2 safe verification flip rate.
    - Detector probability reduction (Δp).
    - Extra token cost and latency overhead.
    - Static analysis delta (Bandit / Cppcheck).
  Option C — Line-Level Explainability (Attention Pooling):
    - Top-1 and Top-3 Line Attribution Hit Rate (identifying vulnerable statements).
    - Attribution inference latency overhead.

Outputs structured benchmark results to:
  results/phase7_evaluation_summary.json
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.model_manager import LocalModelManager
from src.refinement.groq_client import GroqRefinementClient
from src.refinement.self_verification import self_verify_refinement, verify_patch_candidate, run_static_analysis
from src.pipeline.explainability import explain_vulnerability

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phase7_eval")


def run_option_b_self_verification_benchmark(model_mgr: LocalModelManager, groq_client: GroqRefinementClient) -> Dict[str, Any]:
    """
    Benchmark Option B: Self-Verification Loop on diverse multi-language vulnerability pairs.
    """
    logger.info("======================================================================")
    logger.info("BENCHMARKING OPTION B: SELF-VERIFICATION LOOP & PATCH QUALITY GAIN")
    logger.info("======================================================================")

    test_cases = [
        {
            "id": "TC-01",
            "name": "Buffer Overflow (strcpy)",
            "language": "C",
            "tier": "tier1_c_cpp",
            "cwe_id": "CWE-119",
            "code": """void copy_buffer(char *input) {
    char dest[16];
    strcpy(dest, input);
}""",
        },
        {
            "id": "TC-02",
            "name": "SQL Injection (Python f-string)",
            "language": "Python",
            "tier": "tier2_python",
            "cwe_id": "CWE-89",
            "code": """def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)""",
        },
        {
            "id": "TC-03",
            "name": "Command Injection (Python subprocess shell=True)",
            "language": "Python",
            "tier": "tier2_python",
            "cwe_id": "CWE-78",
            "code": """import subprocess
def ping_address(ip_addr):
    subprocess.call("ping -c 1 " + ip_addr, shell=True)""",
        },
        {
            "id": "TC-04",
            "name": "Path Traversal (Go file open)",
            "language": "Go",
            "tier": "tier3_shared",
            "cwe_id": "CWE-22",
            "code": """func ReadLog(filename string) ([]byte, error) {
    return os.ReadFile("/var/log/" + filename)
}""",
        },
        {
            "id": "TC-05",
            "name": "Reflected XSS (PHP raw echo)",
            "language": "PHP",
            "tier": "tier2_php",
            "cwe_id": "CWE-79",
            "code": """<?php
function show_profile($name) {
    echo "<h1>Welcome back, " . $name . "!</h1>";
}
?>""",
        },
        {
            "id": "TC-06",
            "name": "Command Injection (JS child_process.exec)",
            "language": "JavaScript",
            "tier": "tier3_shared",
            "cwe_id": "CWE-78",
            "code": """const { exec } = require('child_process');
function runDiagnostics(target) {
    exec('traceroute ' + target);
}""",
        },
    ]

    results = []
    pass1_safe_count = 0
    pass2_safe_count = 0
    self_corrected_count = 0
    total_extra_tokens = 0
    total_latency = 0.0

    for tc in test_cases:
        logger.info(f"Running Self-Verification test: {tc['id']} ({tc['name']})...")
        t0 = time.time()
        sv_res = self_verify_refinement(
            code=tc["code"],
            language=tc["language"],
            tier=tc["tier"],
            cwe_id=tc["cwe_id"],
            model_manager=model_mgr,
            groq_client=groq_client,
            max_retries=1,
        )
        elapsed = time.time() - t0
        total_latency += elapsed

        status = sv_res.get("status")
        pass1_eval = sv_res.get("pass1_eval") or {}
        pass2_eval = sv_res.get("pass2_eval") or {}
        flip = sv_res.get("flip_to_safe", False)
        extra_tok = sv_res.get("extra_tokens", 0)
        total_extra_tokens += extra_tok

        p1_safe = pass1_eval.get("passed", False)
        if p1_safe:
            pass1_safe_count += 1

        final_safe = sv_res.get("verified_safe", False)
        if final_safe:
            pass2_safe_count += 1

        if flip:
            self_corrected_count += 1

        results.append({
            "id": tc["id"],
            "name": tc["name"],
            "language": tc["language"],
            "status": status,
            "pass1_passed": p1_safe,
            "pass1_prob": pass1_eval.get("prob_vuln"),
            "pass2_passed": pass2_eval.get("passed", False) if pass2_eval else None,
            "pass2_prob": pass2_eval.get("prob_vuln") if pass2_eval else None,
            "flip_to_safe": flip,
            "prob_reduction": sv_res.get("prob_reduction", 0.0),
            "extra_tokens": extra_tok,
            "attempts": sv_res.get("attempts", 1),
            "elapsed_seconds": round(elapsed, 2),
        })

    n = len(test_cases)
    pass1_rate = pass1_safe_count / n
    final_rate = pass2_safe_count / n
    quality_gain = (final_rate - pass1_rate) * 100.0
    avg_extra_tok = total_extra_tokens / n

    summary = {
        "total_test_cases": n,
        "pass1_safe_count": pass1_safe_count,
        "pass1_safe_rate": round(pass1_rate, 4),
        "final_safe_count": pass2_safe_count,
        "final_safe_rate": round(final_rate, 4),
        "self_corrected_count": self_corrected_count,
        "safe_rate_gain_pct": round(quality_gain, 1),
        "avg_extra_tokens": round(avg_extra_tok, 1),
        "avg_latency_seconds": round(total_latency / n, 2),
        "test_cases": results,
    }

    logger.info(f"Option B Summary: Pass 1 Safe: {pass1_rate:.1%} | Final Safe: {final_rate:.1%} | Quality Gain: +{quality_gain:.1f}% | Avg Extra Tokens: {avg_extra_tok:.0f}")
    return summary


def run_option_c_explainability_benchmark(model_mgr: LocalModelManager) -> Dict[str, Any]:
    """
    Benchmark Option C: Attention Pooling Line-Level Attribution against ground truth vulnerable lines.
    """
    logger.info("======================================================================")
    logger.info("BENCHMARKING OPTION C: ATTENTION POOLING LINE ATTRIBUTION")
    logger.info("======================================================================")

    test_cases = [
        {
            "id": "EXP-01",
            "name": "Buffer Overflow strcpy",
            "tier": "tier1_c_cpp",
            "expected_vuln_substring": "strcpy(dest, input);",
            "code": """void copy_buffer(char *input) {
    char dest[16];
    strcpy(dest, input);
}""",
        },
        {
            "id": "EXP-02",
            "name": "SQL Injection f-string",
            "tier": "tier2_python",
            "expected_vuln_substring": "query = f\"SELECT * FROM users",
            "code": """def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)""",
        },
        {
            "id": "EXP-03",
            "name": "Subprocess shell=True",
            "tier": "tier2_python",
            "expected_vuln_substring": "subprocess.call(\"ping",
            "code": """import subprocess
def ping_address(ip_addr):
    subprocess.call("ping -c 1 " + ip_addr, shell=True)""",
        },
        {
            "id": "EXP-04",
            "name": "Path Traversal in Go",
            "tier": "tier3_shared",
            "expected_vuln_substring": "os.ReadFile(\"/var/log/\"",
            "code": """func ReadLog(filename string) ([]byte, error) {
    return os.ReadFile("/var/log/" + filename)
}""",
        },
    ]

    results = []
    top1_hits = 0
    top3_hits = 0
    total_time = 0.0

    for tc in test_cases:
        t0 = time.time()
        pred = model_mgr.predict_binary_vf(tc["code"], tc["tier"])
        elapsed = time.time() - t0
        total_time += elapsed

        exp = pred.get("explainability") or {}
        top_lines = exp.get("top_lines", [])

        # Check Top-1 Hit
        top1_hit = False
        if top_lines:
            top1_hit = tc["expected_vuln_substring"] in top_lines[0]["text"]

        # Check Top-3 Hit
        top3_hit = any(tc["expected_vuln_substring"] in tl["text"] for tl in top_lines[:3])

        if top1_hit:
            top1_hits += 1
        if top3_hit:
            top3_hits += 1

        results.append({
            "id": tc["id"],
            "name": tc["name"],
            "tier": tc["tier"],
            "expected": tc["expected_vuln_substring"],
            "top1_attributed_line": top_lines[0]["text"] if top_lines else None,
            "top1_score": top_lines[0]["score"] if top_lines else 0.0,
            "top1_hit": top1_hit,
            "top3_hit": top3_hit,
            "latency_ms": round(elapsed * 1000, 1),
        })

    n = len(test_cases)
    summary = {
        "total_test_cases": n,
        "top1_accuracy": round(top1_hits / n, 4),
        "top3_accuracy": round(top3_hits / n, 4),
        "avg_attribution_latency_ms": round((total_time / n) * 1000, 1),
        "test_cases": results,
    }

    logger.info(f"Option C Summary: Top-1 Accuracy: {summary['top1_accuracy']:.1%} | Top-3 Accuracy: {summary['top3_accuracy']:.1%} | Avg Latency: {summary['avg_attribution_latency_ms']}ms")
    return summary


def main():
    logger.info("Initializing Phase 7 Evaluation Suite...")
    model_mgr = LocalModelManager(device="cpu")
    groq_client = GroqRefinementClient()

    results_dir = PROJECT_ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "phase7_evaluation_summary.json"

    # Run Option B benchmark
    opt_b_results = run_option_b_self_verification_benchmark(model_mgr, groq_client)

    # Run Option C benchmark
    opt_c_results = run_option_c_explainability_benchmark(model_mgr)

    # Save consolidated results
    phase7_summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "machine": "mac (Apple Silicon MPS/CPU inference, Groq LPU API refinement)",
        "option_b_self_verification": opt_b_results,
        "option_c_explainability": opt_c_results,
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(phase7_summary, f, indent=2)

    logger.info(f"Saved Phase 7 evaluation summary to: {summary_path}")
    print("\n" + "=" * 70)
    print("PHASE 7 BENCHMARK COMPLETE!")
    print(f"Option B: Self-Verification Gain: +{opt_b_results['safe_rate_gain_pct']}% | Final Safe Rate: {opt_b_results['final_safe_rate']:.1%}")
    print(f"Option C: Top-1 Accuracy: {opt_c_results['top1_accuracy']:.1%} | Top-3 Accuracy: {opt_c_results['top3_accuracy']:.1%}")
    print("=" * 70)


if __name__ == "__main__":
    main()

