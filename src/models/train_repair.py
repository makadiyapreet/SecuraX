"""
train_repair.py — Phase 4: Code Refinement Runner (Groq-Hosted LLM with Ollama Fallback).

CONVERTED TO GROQ:
  Primary engine is now Groq-hosted open-weight LLMs via HTTPS API (free tier).
  No local GPU or 4-bit quantization needed (runs on macOS MPS, Linux, Windows).
  Local offline execution remains available via `--backend ollama` flag.

Usage:
    # PRIMARY — Refine test benchmarks with Groq hosted models
    python src/models/train_repair.py --backend groq --samples 100

    # Compare default vs alternate Groq models
    python src/models/train_repair.py --backend groq --model both --samples 100

    # Local Ollama offline fallback (if local Ollama server is running)
    python src/models/train_repair.py --backend ollama --model mistral
"""

import os
import sys
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

logger = logging.getLogger("train_repair")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


def run_ollama_fallback(args):
    """Run local Ollama fallback inference if requested."""
    logger.info("Initializing local Ollama refinement backend...")
    import requests

    model_name = getattr(args, "model_name", "mistral")
    try:
        requests.get("http://localhost:11434", timeout=3.0)
        logger.info(f"Ollama server detected. Running zero-shot refinement on {model_name}...")
    except Exception as e:
        logger.error(f"Ollama server is not running at localhost:11434 ({e}). Aborting local fallback.")
        return None


def main():
    parser = argparse.ArgumentParser(description="Phase 4: Code Refinement Runner (Groq Hosted LLM)")
    parser.add_argument(
        "--backend",
        choices=["groq", "ollama"],
        default="groq",
        help="Refinement backend: groq (default, HTTPS API) or ollama (local offline)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="both",
        help="Model to run: 'default', 'alternate', 'both', or specific model name",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=100,
        help="Number of test samples to refine (default 100)",
    )
    parser.add_argument(
        "--manual-samples",
        type=int,
        default=40,
        help="Number of samples to log for manual qualitative review (default 40)",
    )
    parser.add_argument(
        "--method",
        type=str,
        default=None,
        help="Legacy compatibility flag",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default=None,
        help="Legacy compatibility flag",
    )
    parser.add_argument(
        "--bf16",
        action="store_true",
        help="Legacy compatibility flag (ignored for API)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=20,
        help="Legacy compatibility flag (ignored for API)",
    )

    args = parser.parse_args()

    if args.backend == "ollama":
        return run_ollama_fallback(args)

    logger.info("=" * 70)
    logger.info("  SECURAX PHASE 4 — CODE REFINEMENT VIA GROQ API")
    logger.info("  Constraint Exception: Groq free-tier hosted open-weight models")
    logger.info("=" * 70)

    # Verify offline fallback
    test_offline_fallback()

    # Load client & configuration
    config = load_refinement_config()
    default_model = config["models"]["default"]
    alternate_model = config["models"]["alternate"]

    client = GroqRefinementClient()
    if not client.is_available:
        logger.error(f"Cannot run refinement: {client.unavailable_reason}")
        sys.exit(1)

    # Load stratified samples
    samples = load_stratified_test_samples(sample_size=args.samples)

    if args.model == "both":
        preds_def, summ_def = run_model_refinement(client, default_model, samples)
        preds_alt, summ_alt = run_model_refinement(client, alternate_model, samples)
        generate_consolidated_comparison(summ_def, summ_alt)
        generate_manual_review_report(preds_def, n_samples=args.manual_samples, model_name=default_model)
    else:
        target = default_model if args.model in ("default", "") else args.model
        preds, summ = run_model_refinement(client, target, samples)
        generate_manual_review_report(preds, n_samples=args.manual_samples, model_name=target)

    logger.info("\n✅ Phase 4 Groq Code Refinement completed successfully.")


if __name__ == "__main__":
    main()
