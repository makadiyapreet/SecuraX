"""
run_phase4_all.py — Phase 4 Orchestrator: Complete Groq Code Refinement Pipeline.

Runs all Phase 4 steps end-to-end:
  1. Offline / rate-limit fallback test verification
  2. Groq Refinement on 100 stratified multi-language test samples (Default Model)
  3. Groq Refinement on the same samples with Alternate Model
  4. Ground-Truth (EM, Edit Similarity, BLEU) & Proxy Evaluation (Syntax, VF Flip, Bandit/Cppcheck)
  5. Cross-Model Comparison & Winner Selection
  6. Qualitative Manual Review Report (40 samples across >=3 languages)

Usage:
    # Full execution across both models
    python src/models/run_phase4_all.py

    # Quick dry run
    python src/models/run_phase4_all.py --dry-run

    # Run specific sample size
    python src/models/run_phase4_all.py --samples 50
"""

import os
import sys
import time
import argparse
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.refinement.run_refinement import (
    load_stratified_test_samples,
    run_model_refinement,
    generate_consolidated_comparison,
    generate_manual_review_report,
    test_offline_fallback,
)
from src.refinement.groq_client import (
    GroqRefinementClient,
    load_refinement_config,
)

logger = logging.getLogger("run_phase4_all")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


def main():
    parser = argparse.ArgumentParser(description="Phase 4 Orchestrator: Full Groq Refinement Pipeline")
    parser.add_argument("--samples", type=int, default=100, help="Number of benchmark test samples (default 100)")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without invoking API")
    parser.add_argument("--manual-samples", type=int, default=40, help="Number of manual review samples (default 40)")
    parser.add_argument("--bf16", action="store_true", help="Legacy compatibility flag (ignored for API)")
    parser.add_argument("--epochs", type=int, default=20, help="Legacy compatibility flag (ignored for API)")
    args = parser.parse_args()

    config = load_refinement_config()
    default_model = config["models"]["default"]
    alternate_model = config["models"]["alternate"]

    print("=" * 75)
    print("  SECURAX — PHASE 4: CODE REFINEMENT ORCHESTRATOR (GROQ API)")
    print(f"  Default Model:   {default_model}")
    print(f"  Alternate Model: {alternate_model}")
    print(f"  Benchmark Size:  {args.samples} stratified samples across >=8 languages")
    print(f"  Mode:            {'DRY RUN' if args.dry_run else 'EXECUTE'}")
    print("=" * 75)

    if args.dry_run:
        print("\n[DRY RUN PLAN]")
        print("1. Verify offline/rate-limit fallback without throwing exceptions")
        print(f"2. Run {default_model} on {args.samples} samples (cached to data/cache/groq/)")
        print(f"3. Run {alternate_model} on identical {args.samples} samples")
        print("4. Compute Ground-Truth (EM, Edit Sim, BLEU) and Proxy (Syntax, VF Flip) metrics")
        print("5. Generate consolidated comparison report in results/phase4_code_repair_results.md")
        print(f"6. Generate manual review report ({args.manual_samples} samples) in results/phase4_manual_review.md")
        print("7. Select winning model for Phase 5 integration")
        print("\n[DRY RUN COMPLETE] — No API calls executed.")
        return

    # Step 1: Offline Fallback Verification
    logger.info("\n[Step 1/5] Verifying offline / rate-limit fallback...")
    test_offline_fallback()

    # Step 2: Initialize client
    client = GroqRefinementClient()
    if not client.is_available:
        logger.error(f"Cannot proceed with Phase 4: {client.unavailable_reason}")
        sys.exit(1)

    # Step 3: Load stratified samples
    logger.info(f"\n[Step 2/5] Loading {args.samples} stratified test samples...")
    samples = load_stratified_test_samples(sample_size=args.samples)

    # Step 4: Run both models
    logger.info(f"\n[Step 3/5] Running refinement on Default Model: {default_model}...")
    preds_def, summ_def = run_model_refinement(client, default_model, samples)

    logger.info(f"\n[Step 4/5] Running refinement on Alternate Model: {alternate_model}...")
    preds_alt, summ_alt = run_model_refinement(client, alternate_model, samples)

    # Step 5: Reports and Review
    logger.info("\n[Step 5/5] Generating consolidated comparison & manual review reports...")
    generate_consolidated_comparison(summ_def, summ_alt)
    generate_manual_review_report(preds_def, n_samples=args.manual_samples, model_name=default_model)

    print("\n" + "=" * 75)
    print("  PHASE 4 COMPLETE — SUMMARY OF RESULTS")
    print("=" * 75)
    print(f"  Default Model:    {default_model}")
    print(f"    - Perfect Pred: {summ_def['overall']['perfect_prediction']*100:.1f}%")
    print(f"    - Edit Sim:     {summ_def['overall']['edit_similarity']:.3f}")
    print(f"    - Syntax Valid: {summ_def['overall']['syntax_validity']*100:.1f}%")
    print(f"    - VF Flip Rate: {summ_def['overall']['vf_flip_rate']*100:.1f}%")
    print(f"\n  Alternate Model:  {alternate_model}")
    print(f"    - Perfect Pred: {summ_alt['overall']['perfect_prediction']*100:.1f}%")
    print(f"    - Edit Sim:     {summ_alt['overall']['edit_similarity']:.3f}")
    print(f"    - Syntax Valid: {summ_alt['overall']['syntax_validity']*100:.1f}%")
    print(f"    - VF Flip Rate: {summ_alt['overall']['vf_flip_rate']*100:.1f}%")
    print("=" * 75)
    print("  Output artifacts:")
    print("    - results/phase4_code_repair_results.md")
    print("    - results/phase4_manual_review.md")
    print("    - logs/phase4_predictions_*.json")
    print("    - logs/phase4_refinement_results_*.json")
    print("=" * 75)


if __name__ == "__main__":
    main()
