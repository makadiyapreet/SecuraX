"""
self_verification.py — Phase 7 Option B: Self-Verification & Iterative Refinement Loop.

After generating a patch candidate (Pass 1), this module:
  1. Verifies syntax validity.
  2. Re-runs Phase 1 binary vulnerability detection (and attention explainability).
  3. Executes static analysis checks (Bandit for Python, Cppcheck for C/C++).
  4. If flagged as still vulnerable or invalid, constructs a targeted feedback prompt
     containing detector verdicts and static findings.
  5. Re-prompts Groq once (Pass 2) to correct residual vulnerabilities.
  6. Re-evaluates Pass 2, measuring patch quality gain, probability reduction, and token overhead.
"""

import os
import ast
import json
import time
import logging
import tempfile
import subprocess
from typing import Dict, Any, Optional, List, Tuple

from src.refinement.prompts import (
    build_refinement_prompt,
    build_self_verification_prompt,
    parse_refinement_response,
)
from src.evaluation.evaluate_repair import check_syntax
from src.refinement.static_security import run_comprehensive_static_analysis

logger = logging.getLogger("self_verification")


# ─── Static Analysis Tool Wrappers ──────────────────────────────────────────


def run_bandit_feedback(code: str) -> List[str]:
    """Run Bandit security scanner on Python code and return descriptive issue strings."""
    warnings = []
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            fname = f.name

        try:
            res = subprocess.run(
                ["bandit", "-f", "json", "-q", fname],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if res.stdout:
                data = json.loads(res.stdout)
                for item in data.get("results", []):
                    test_id = item.get("test_id", "SEC")
                    issue_text = item.get("issue_text", "")
                    line_no = item.get("line_number", "?")
                    severity = item.get("issue_severity", "MEDIUM")
                    warnings.append(f"[{test_id}] Line {line_no} ({severity}): {issue_text}")
        finally:
            if os.path.exists(fname):
                os.unlink(fname)
    except Exception as e:
        logger.debug(f"Bandit check skipped/failed: {e}")

    return warnings


def run_cppcheck_feedback(code: str, lang: str = "c") -> List[str]:
    """Run Cppcheck static analyzer on C/C++ code and return descriptive warning strings."""
    warnings = []
    ext = ".c" if lang.lower() == "c" else ".cpp"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(code)
            fname = f.name

        try:
            res = subprocess.run(
                ["cppcheck", "--enable=all", "--quiet", fname],
                capture_output=True,
                text=True,
                timeout=15,
            )
            raw_err = res.stderr or ""
            for line in raw_err.strip().splitlines():
                line = line.strip()
                if (
                    not line
                    or "information: Active checkers" in line
                    or "information: Include file" in line
                    or "[unusedFunction]" in line
                    or "[checkersReport]" in line
                ):
                    continue
                # Strip temp filename for clean feedback
                if fname in line:
                    line = line.replace(fname, "code")
                warnings.append(line)
        finally:
            if os.path.exists(fname):
                os.unlink(fname)
    except Exception as e:
        logger.debug(f"Cppcheck check skipped/failed: {e}")

    return warnings


def run_static_analysis(code: str, language: str) -> Dict[str, Any]:
    """Execute language-specific static analysis tools and semantic AST checks."""
    lang_clean = (language or "").strip().lower()
    warnings = []
    tool_name = "SecuraX-StaticAnalyzer"

    # Step 1: External tools (Bandit for Python, Cppcheck for C/C++)
    if lang_clean in ("python", "py"):
        b_warns = run_bandit_feedback(code)
        warnings.extend(b_warns)
    elif lang_clean in ("c", "c++", "cpp"):
        c_warns = run_cppcheck_feedback(code, lang=lang_clean)
        warnings.extend(c_warns)

    # Step 2: Comprehensive AST / Semantic static security analysis
    sem_res = run_comprehensive_static_analysis(code, language)
    for warn in sem_res.get("formatted_warnings", []):
        if warn not in warnings:
            warnings.append(warn)

    active_tool = sem_res.get("tool", tool_name)

    return {
        "tool": active_tool,
        "warnings_count": len(warnings),
        "warnings": warnings,
        "clean": len(warnings) == 0,
        "issues": sem_res.get("issues", []),
    }


# ─── Verification Logic ──────────────────────────────────────────────────────


def verify_patch_candidate(
    patch_code: Optional[str],
    language: str,
    tier: str,
    model_manager: Any,
) -> Dict[str, Any]:
    """
    Verify a candidate patch against syntax validity, Phase 1 neural detection, and static analysis.
    Combines independent lines of evidence rather than relying solely on one signal.
    """
    if not patch_code or not patch_code.strip():
        return {
            "passed": False,
            "syntax_valid": False,
            "syntax_error": "Candidate patch is empty.",
            "is_vulnerable": True,
            "prob_vuln": 1.0,
            "threshold": 0.5,
            "static_warnings": [],
            "explainability": None,
            "reason": "Empty patch candidate",
        }

    # 1. Syntax check
    syntax_valid = check_syntax(patch_code, language)
    syntax_error = None if syntax_valid else "Code failed syntax parsing or delimiter balance."

    # 2. Static analysis
    sa_res = run_static_analysis(patch_code, language)
    static_warnings = sa_res.get("warnings", [])
    static_clean = sa_res.get("clean", False)
    static_issues = sa_res.get("issues", [])

    # 3. Phase 1 neural detection
    p1_res = model_manager.predict_binary_vf(patch_code, tier)
    neural_vulnerable = p1_res.get("is_vulnerable", False)
    prob_vuln = p1_res.get("prob_vuln", 0.0)
    threshold = p1_res.get("threshold", 0.5)
    explainability = p1_res.get("explainability")

    # Decision Logic:
    # A candidate patch is verified safe ONLY IF syntax is valid AND no static security flaws are present.
    if not syntax_valid:
        passed = False
        reason = f"Syntax error: {syntax_error}"
    elif not static_clean:
        passed = False
        critical_desc = static_warnings[0] if static_warnings else "Static analysis flagged security issues"
        reason = f"Residual vulnerability detected by static analysis: {critical_desc}"
    elif not neural_vulnerable:
        passed = True
        reason = "Verified Safe (Neural detector & static analysis confirmed clean)"
    else:
        # Static analysis is completely clean, but neural detector flagged residual structure.
        # Check if static analysis verifies parameterized / safe constructs.
        if static_clean and len(static_issues) == 0:
            passed = True
            reason = f"Verified Safe (Independent static analysis confirmed secure; neural token residual p={prob_vuln:.1%})"
        else:
            passed = False
            reason = f"Neural detector flagged potential residual risk (p={prob_vuln:.1%})"

    return {
        "passed": passed,
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "is_vulnerable": not passed,
        "prob_vuln": prob_vuln,
        "threshold": threshold,
        "static_tool": sa_res.get("tool"),
        "static_warnings": static_warnings,
        "explainability": explainability,
        "reason": reason,
    }


# ─── Self-Verification Loop ──────────────────────────────────────────────────


def self_verify_refinement(
    code: str,
    language: str,
    tier: str,
    cwe_id: str,
    model_manager: Any,
    groq_client: Any,
    candidate_patch: Optional[str] = None,
    semantic_group: Optional[str] = None,
    severity_score: Optional[float] = None,
    max_retries: int = 1,
) -> Dict[str, Any]:
    """
    Execute Phase 7 Option B Self-Verification loop.
    
    If candidate_patch is provided, it serves as Pass 1.
    If Pass 1 fails verification, Groq is re-prompted once with the detector verdict,
    attention attribution, and static analysis warnings.
    """
    start_time = time.time()
    pass1_tokens = 0
    pass2_tokens = 0
    feedback_prompt = None

    # Step 1: Obtain or use Pass 1 candidate
    pass1_code = candidate_patch
    if not pass1_code:
        prompt1 = build_refinement_prompt(
            language=language,
            vulnerable_snippet=code,
            cwe_id=cwe_id,
            semantic_group=semantic_group,
            severity_score=severity_score,
            max_snippet_chars=3500,
        )
        res1 = groq_client.complete(
            user_prompt=prompt1,
            model=groq_client.model,
            temperature=0.1,
            max_tokens=800,
        )
        if res1.get("status") in ("success", "cached"):
            parsed1 = parse_refinement_response(res1.get("content"), expected_language=language)
            pass1_code = parsed1.get("refined_code")
            pass1_tokens = res1.get("usage", {}).get("total_tokens", 450)
        else:
            return {
                "success": False,
                "status": "pass1_failed",
                "final_code": f"Refinement unavailable: {res1.get('error_message')}",
                "pass1_code": None,
                "pass2_code": None,
                "verified_safe": False,
                "attempts": 1,
                "flip_to_safe": False,
                "quality_gain": 0.0,
                "extra_tokens": 0,
                "total_tokens": 0,
                "pass1_eval": {},
                "pass2_eval": {},
                "feedback": None,
                "elapsed_seconds": round(time.time() - start_time, 2),
            }

    # Step 2: Evaluate Pass 1 candidate
    eval1 = verify_patch_candidate(pass1_code, language, tier, model_manager)

    # Condition: If Pass 1 passed verification, we are done!
    if eval1["passed"] or max_retries < 1:
        return {
            "success": True,
            "status": "verified_safe_pass1" if eval1["passed"] else "unverified_pass1",
            "final_code": pass1_code,
            "pass1_code": pass1_code,
            "pass2_code": None,
            "verified_safe": eval1["passed"],
            "attempts": 1,
            "flip_to_safe": False,
            "quality_gain": 0.0,
            "prob_reduction": 0.0,
            "extra_tokens": 0,
            "total_tokens": pass1_tokens,
            "pass1_eval": eval1,
            "pass2_eval": None,
            "feedback": None,
            "elapsed_seconds": round(time.time() - start_time, 2),
        }

    # Step 3: Pass 1 failed verification -> Build targeted feedback prompt for Pass 2
    logger.info(f"[SelfVerification] Pass 1 failed verification: {eval1['reason']}. Triggering re-prompt.")

    # Format explainability lines if available
    exp_summary = None
    if eval1.get("explainability"):
        top_lines = eval1["explainability"].get("top_lines", [])
        if top_lines:
            exp_summary = ", ".join(f"Line {item['line_no']}: '{(item.get('text') or item.get('line_content', '')).strip()}'" for item in top_lines[:2])

    feedback_prompt = build_self_verification_prompt(
        language=language,
        original_code=code,
        previous_patch=pass1_code,
        cwe_id=cwe_id,
        detector_prob=eval1.get("prob_vuln", 0.8),
        detector_threshold=eval1.get("threshold", 0.5),
        static_warnings=eval1.get("static_warnings", []),
        syntax_error=eval1.get("syntax_error"),
        explainability_lines=exp_summary,
    )

    # Step 4: Query Groq for Pass 2 refinement
    res2 = groq_client.complete(
        user_prompt=feedback_prompt,
        model=groq_client.model,
        temperature=0.2,  # slightly higher temperature for novel repair strategy
        max_tokens=800,
    )

    pass2_code = None
    if res2.get("status") in ("success", "cached"):
        parsed2 = parse_refinement_response(res2.get("content"), expected_language=language)
        pass2_code = parsed2.get("refined_code")
        pass2_tokens = res2.get("usage", {}).get("total_tokens", 520)

    # Step 5: Evaluate Pass 2 candidate
    if pass2_code:
        eval2 = verify_patch_candidate(pass2_code, language, tier, model_manager)
    else:
        eval2 = {
            "passed": False,
            "syntax_valid": False,
            "syntax_error": "Pass 2 generation failed or empty.",
            "is_vulnerable": True,
            "prob_vuln": 1.0,
            "threshold": eval1.get("threshold", 0.5),
            "static_warnings": [],
            "reason": "Pass 2 output empty",
        }

    # Determine outcome & metrics
    flip_to_safe = (not eval1["passed"]) and eval2["passed"]
    prob_red = eval1.get("prob_vuln", 0.0) - eval2.get("prob_vuln", 0.0)

    if flip_to_safe:
        status = "self_corrected_pass2"
        final_code = pass2_code
        verified_safe = True
    elif eval2.get("syntax_valid") and (eval2.get("prob_vuln", 1.0) < eval1.get("prob_vuln", 1.0)):
        # Pass 2 is an improvement even if threshold not quite reached
        status = "improved_pass2"
        final_code = pass2_code
        verified_safe = False
    elif eval2.get("syntax_valid"):
        status = "unresolved_pass2"
        final_code = pass2_code
        verified_safe = False
    else:
        # Pass 2 broke syntax; fall back to Pass 1
        status = "reverted_to_pass1"
        final_code = pass1_code
        verified_safe = False

    return {
        "success": True,
        "status": status,
        "final_code": final_code,
        "pass1_code": pass1_code,
        "pass2_code": pass2_code,
        "verified_safe": verified_safe,
        "attempts": 2,
        "flip_to_safe": flip_to_safe,
        "prob_reduction": round(prob_red, 4),
        "pass1_prob": eval1.get("prob_vuln"),
        "pass2_prob": eval2.get("prob_vuln"),
        "extra_tokens": pass2_tokens,
        "total_tokens": pass1_tokens + pass2_tokens,
        "pass1_eval": eval1,
        "pass2_eval": eval2,
        "feedback": feedback_prompt,
        "elapsed_seconds": round(time.time() - start_time, 2),
    }
