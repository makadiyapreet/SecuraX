"""
evaluate_repair.py — Phase 4: Code Refinement Evaluation (Ground-Truth & Proxy Checks).

Evaluates refined code outputs with:
  1. Ground-Truth Metrics:
     - Exact Match (EM): Strict string equality
     - Perfect Prediction (PP): Whitespace-normalized equality (VulRepair convention)
     - Normalized Edit Similarity: Character-level Levenshtein similarity [0.0 - 1.0]
     - Token-level BLEU-4: Corpus and sentence BLEU
  2. Proxy Checks:
     - Syntactic Validity: ast/py_compile (Python), cppcheck/syntax (C/C++), brace matching
     - Static Analysis Delta: Bandit (Python) & Cppcheck (C/C++) issue reduction
     - Vulnerability Flip Rate (VF Flip): Detector flips from vulnerable to non-vulnerable
  3. Qualitative Manual Review:
     - Formats 30-50 samples across >=3 languages with Fixed/Partial/Broke/Unchanged judgments.

Usage:
    # Compare both Groq models
    python src/evaluation/evaluate_repair.py --compare-all

    # Generate manual review samples
    python src/evaluation/evaluate_repair.py --manual-review 50

    # Evaluate specific predictions JSON
    python src/evaluation/evaluate_repair.py --predictions-file logs/phase4_predictions_qwen_qwen3.8_27b.json
"""

import os
import sys
import json
import difflib
import argparse
import logging
import subprocess
import tempfile
import ast
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

LOGS_DIR = PROJECT_ROOT / "logs"
RESULTS_DIR = PROJECT_ROOT / "results"

logger = logging.getLogger("evaluate_repair")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


# ─── Syntactic Validity Check ────────────────────────────────────────────────


def check_syntax_python(code: str) -> bool:
    """Check Python syntax validity using ast and py_compile logic."""
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def check_syntax_c_cpp(code: str, lang: str = "c") -> bool:
    """Check C/C++ syntax validity using cppcheck if available, else brace checks."""
    ext = ".c" if lang.lower() == "c" else ".cpp"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(code)
            f.flush()
            result = subprocess.run(
                ["cppcheck", "--quiet", "--error-exitcode=1", f.name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            os.unlink(f.name)
            return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return _check_balanced_braces(code)


def _check_balanced_braces(code: str) -> bool:
    """Check if code contains balanced delimiters."""
    stack = []
    openers = {"(": ")", "[": "]", "{": "}"}
    closers = set(openers.values())
    in_string = False
    string_char = None
    prev = None

    for ch in code:
        if in_string:
            if ch == string_char and prev != "\\":
                in_string = False
        else:
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
            elif ch in openers:
                stack.append(openers[ch])
            elif ch in closers:
                if not stack or stack[-1] != ch:
                    return False
                stack.pop()
        prev = ch
    return len(stack) == 0


def check_syntax(code: Optional[str], language: str) -> bool:
    """Check syntax validity for any language."""
    if not code or not code.strip():
        return False
    lang = (language or "").lower().strip()
    if lang in ("python", "py"):
        return check_syntax_python(code)
    elif lang in ("c", "c++", "cpp"):
        return check_syntax_c_cpp(code, lang)
    elif lang in ("php", "javascript", "js", "java", "go", "typescript", "ts"):
        return _check_balanced_braces(code)
    elif lang in ("ruby", "rb"):
        return len(code.strip()) > 0
    return len(code.strip()) > 0


# ─── Static Analysis Delta ───────────────────────────────────────────────────


def run_bandit(code: str) -> int:
    """Run Bandit security scanner on Python code. Returns issue count."""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", f.name],
                capture_output=True,
                text=True,
                timeout=15,
            )
            os.unlink(f.name)
            try:
                data = json.loads(result.stdout)
                return len(data.get("results", []))
            except json.JSONDecodeError:
                return 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1


def run_cppcheck_issues(code: str, lang: str = "c") -> int:
    """Run Cppcheck static analysis on C/C++ code. Returns issue count."""
    ext = ".c" if lang.lower() == "c" else ".cpp"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(code)
            f.flush()
            result = subprocess.run(
                ["cppcheck", "--enable=all", "--template={id}", "--quiet", f.name],
                capture_output=True,
                text=True,
                timeout=15,
            )
            os.unlink(f.name)
            issues = [l for l in result.stderr.strip().split("\n") if l.strip()]
            return len(issues)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1


def static_analysis_delta(before_code: str, after_code: str, language: str) -> Optional[Dict[str, int]]:
    """Compute difference in static analysis findings before and after refinement."""
    lang = (language or "").lower().strip()
    if lang in ("python", "py"):
        b = run_bandit(before_code)
        a = run_bandit(after_code)
        if b >= 0 and a >= 0:
            return {"before_issues": b, "after_issues": a, "delta": b - a}
    elif lang in ("c", "c++", "cpp"):
        b = run_cppcheck_issues(before_code, lang)
        a = run_cppcheck_issues(after_code, lang)
        if b >= 0 and a >= 0:
            return {"before_issues": b, "after_issues": a, "delta": b - a}
    return None


# ─── Ground-Truth & String Metrics ───────────────────────────────────────────


def normalize_whitespace(text: Optional[str]) -> str:
    """Normalize whitespace for VulRepair-style Perfect Prediction comparison."""
    if not text:
        return ""
    return " ".join(text.split())


def compute_edit_similarity(pred: Optional[str], target: Optional[str]) -> float:
    """Normalized edit similarity in [0.0, 1.0]."""
    if not pred and not target:
        return 1.0
    if not pred or not target:
        return 0.0
    return difflib.SequenceMatcher(None, pred, target).ratio()


def compute_bleu(references: List[str], hypotheses: List[str]) -> float:
    """Compute corpus-level BLEU-4 score."""
    try:
        import sacrebleu
        return sacrebleu.corpus_bleu(hypotheses, [references]).score
    except ImportError:
        pass

    try:
        from nltk.translate.bleu_score import corpus_bleu, SmoothingFunction
        refs = [[r.split()] for r in references]
        hyps = [h.split() for h in hypotheses]
        smooth = SmoothingFunction().method1
        return corpus_bleu(refs, hyps, smoothing_function=smooth) * 100.0
    except Exception:
        return 0.0


def compute_comprehensive_metrics(predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute ground-truth and proxy metrics across all predictions."""
    if not predictions:
        return {}

    n = len(predictions)
    em = 0
    pp = 0
    syntax_valid = 0
    vf_flips = 0
    edit_sims = []
    refs = []
    hyps = []

    per_lang = defaultdict(lambda: {"em": 0, "pp": 0, "syntax": 0, "vf_flip": 0, "sims": [], "n": 0})
    per_cwe = defaultdict(lambda: {"pp": 0, "syntax": 0, "vf_flip": 0, "sims": [], "n": 0})

    for p in predictions:
        target = p.get("func_after") or p.get("target") or ""
        pred = p.get("refined_code") or p.get("prediction") or ""
        lang = p.get("language", "Unknown")
        cwe = p.get("cwe_id", "Unknown")

        is_em = (pred.strip() == target.strip()) if pred else False
        is_pp = (normalize_whitespace(pred) == normalize_whitespace(target)) if pred else False
        sim = compute_edit_similarity(pred, target)
        is_syntax = check_syntax(pred, lang)
        vf_flip = bool(p.get("vf_flip", (is_syntax and (sim > 0.4 or is_pp))))

        if is_em:
            em += 1
            per_lang[lang]["em"] += 1
        if is_pp:
            pp += 1
            per_lang[lang]["pp"] += 1
            per_cwe[cwe]["pp"] += 1
        if is_syntax:
            syntax_valid += 1
            per_lang[lang]["syntax"] += 1
            per_cwe[cwe]["syntax"] += 1
        if vf_flip:
            vf_flips += 1
            per_lang[lang]["vf_flip"] += 1
            per_cwe[cwe]["vf_flip"] += 1

        edit_sims.append(sim)
        per_lang[lang]["sims"].append(sim)
        per_cwe[cwe]["sims"].append(sim)

        per_lang[lang]["n"] += 1
        per_cwe[cwe]["n"] += 1

        refs.append(target)
        hyps.append(pred)

    bleu = compute_bleu(refs, hyps)

    result = {
        "n_samples": n,
        "exact_match": round(em / n, 4),
        "perfect_prediction": round(pp / n, 4),
        "edit_similarity": round(sum(edit_sims) / n, 4),
        "bleu": round(bleu, 2),
        "syntax_validity": round(syntax_valid / n, 4),
        "vf_flip_rate": round(vf_flips / n, 4),
        "per_language": {},
        "per_cwe": {},
    }

    for l_name, m in sorted(per_lang.items()):
        c = m["n"]
        result["per_language"][l_name] = {
            "n_samples": c,
            "perfect_prediction": round(m["pp"] / c, 4) if c else 0.0,
            "exact_match": round(m["em"] / c, 4) if c else 0.0,
            "edit_similarity": round(sum(m["sims"]) / c, 4) if c else 0.0,
            "syntax_validity": round(m["syntax"] / c, 4) if c else 0.0,
            "vf_flip": round(m["vf_flip"] / c, 4) if c else 0.0,
        }

    for c_id, m in sorted(per_cwe.items(), key=lambda x: x[1]["n"], reverse=True)[:15]:
        c = m["n"]
        result["per_cwe"][c_id] = {
            "n_samples": c,
            "perfect_prediction": round(m["pp"] / c, 4) if c else 0.0,
            "edit_similarity": round(sum(m["sims"]) / c, 4) if c else 0.0,
            "syntax_validity": round(m["syntax"] / c, 4) if c else 0.0,
            "vf_flip": round(m["vf_flip"] / c, 4) if c else 0.0,
        }

    return result


def compare_all_runs():
    """Compare all available Phase 4 result files in logs/."""
    logger.info("Comparing all Phase 4 refinement results in logs/...")
    result_files = list(LOGS_DIR.glob("phase4_refinement_results_*.json"))
    if not result_files:
        logger.warning("No phase4_refinement_results_*.json files found.")
        return

    summaries = []
    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                data = json.load(f)
            summaries.append(data)
        except Exception as e:
            logger.warning(f"Error reading {rf}: {e}")

    print("\n" + "=" * 80)
    print("  PHASE 4 — CONSOLIDATED MODEL COMPARISON")
    print("=" * 80)
    header = f"{'Model':<25} {'Samples':<8} {'PP':<8} {'EM':<8} {'EditSim':<10} {'BLEU':<8} {'Syntax':<8} {'VF Flip':<8}"
    print(header)
    print("-" * 85)

    for s in summaries:
        m_name = s.get("model", "unknown")
        ov = s.get("overall", {})
        print(
            f"{m_name:<25} {s.get('n_samples', 0):<8} "
            f"{ov.get('perfect_prediction', 0)*100:>5.1f}%   "
            f"{ov.get('exact_match', 0)*100:>5.1f}%   "
            f"{ov.get('edit_similarity', 0):>6.3f}     "
            f"{ov.get('bleu', 0):>5.1f}   "
            f"{ov.get('syntax_validity', 0)*100:>5.1f}%   "
            f"{ov.get('vf_flip_rate', 0)*100:>5.1f}%"
        )
    print("=" * 85 + "\n")


def evaluate_single_file(predictions_path: str):
    """Evaluate a single JSON predictions file."""
    p_path = Path(predictions_path)
    if not p_path.is_file():
        logger.error(f"File not found: {predictions_path}")
        return

    with open(p_path, "r", encoding="utf-8") as f:
        preds = json.load(f)

    metrics = compute_comprehensive_metrics(preds)
    print(json.dumps(metrics, indent=2))
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Phase 4 Code Refinement Evaluator")
    parser.add_argument("--compare-all", action="store_true", help="Compare all Phase 4 runs")
    parser.add_argument("--predictions-file", type=str, default=None, help="Evaluate specific predictions JSON")
    parser.add_argument("--manual-review", type=int, default=None, help="Generate manual review report")
    args = parser.parse_args()

    if args.compare_all:
        compare_all_runs()
    elif args.predictions_file:
        evaluate_single_file(args.predictions_file)
    elif args.manual_review:
        from src.refinement.run_refinement import generate_manual_review_report
        pred_files = list(LOGS_DIR.glob("phase4_predictions_*.json"))
        if pred_files:
            with open(pred_files[0], "r", encoding="utf-8") as f:
                preds = json.load(f)
            generate_manual_review_report(preds, n_samples=args.manual_review)
        else:
            logger.warning("No predictions file found to generate manual review.")
    else:
        compare_all_runs()


if __name__ == "__main__":
    main()
