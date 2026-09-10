"""
evaluate_binary.py — Evaluate and compare binary vulnerability detection models.

Supports:
  1. Evaluating a single model on the test set
  2. Comparing CodeT5 vs GraphCodeBERT results side-by-side
  3. Selecting the winning backbone for Phase 2+

Usage:
    # Evaluate individual models
    python src/evaluation/evaluate_binary.py --model codet5
    python src/evaluation/evaluate_binary.py --model graphcodebert

    # Compare both models and select winner
    python src/evaluation/evaluate_binary.py --compare

    # Quick inference demo on a code snippet
    python src/evaluation/evaluate_binary.py --predict --model codet5 \\
        --code "int main() { char buf[10]; gets(buf); return 0; }"
"""

<<<<<<< HEAD
import os
=======
# Disable TensorFlow — prevents mutex deadlock on macOS (see train_binary.py)
import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"
>>>>>>> 7861432 (Phase 1 completed)
import sys
import json
import argparse
import shutil
from datetime import datetime
from typing import Dict, Optional

import numpy as np
import torch

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


# ─── Result loading ─────────────────────────────────────────────────────────


def load_results(model_key: str) -> Optional[Dict]:
    """Load training results for a model from the logs directory."""
    path = os.path.join(LOGS_DIR, f"phase1_{model_key}_results.json")
    if not os.path.exists(path):
        print(f"  ⚠️  Results not found: {path}")
        print(f"  Run training first: python src/models/train_binary.py --model {model_key}")
        return None

    with open(path, "r") as f:
        return json.load(f)


# ─── Comparison ──────────────────────────────────────────────────────────────


def compare_models() -> Dict:
    """Compare CodeT5 vs GraphCodeBERT results and select a winner.

    Returns:
        dict with comparison table and winner info
    """
    print("\n" + "=" * 70)
    print("  PHASE 1 — MODEL COMPARISON: CodeT5 vs GraphCodeBERT")
    print("=" * 70)

    codet5_results = load_results("codet5")
    gcb_results = load_results("graphcodebert")

    if codet5_results is None or gcb_results is None:
        print("\n  ❌ Cannot compare — results missing for one or both models.")
        print("  Train both models first, then re-run with --compare.")
        return {}

    # Extract test metrics
    c5 = codet5_results["test_metrics"]
    gcb = gcb_results["test_metrics"]

    # Print comparison table
    print(f"\n  {'Metric':<15} {'CodeT5':>12} {'GraphCodeBERT':>15} {'Winner':>10}")
    print(f"  {'-'*55}")

    metrics_to_compare = [
        ("Recall ★", "recall"),
        ("Precision", "precision"),
        ("F1", "f1"),
        ("AUROC", "auroc"),
        ("Accuracy", "accuracy"),
        ("Loss ↓", "loss"),
    ]

    scores = {"codet5": 0, "graphcodebert": 0}

    for display_name, key in metrics_to_compare:
        c5_val = c5.get(key, 0)
        gcb_val = gcb.get(key, 0)

        # For loss, lower is better
        if key == "loss":
            winner = "CodeT5" if c5_val < gcb_val else "GraphCodeBERT"
            if c5_val < gcb_val:
                scores["codet5"] += 1
            elif gcb_val < c5_val:
                scores["graphcodebert"] += 1
        else:
            winner = "CodeT5" if c5_val > gcb_val else "GraphCodeBERT"
            if c5_val > gcb_val:
                scores["codet5"] += 1
            elif gcb_val > c5_val:
                scores["graphcodebert"] += 1

        if c5_val == gcb_val:
            winner = "Tie"

        print(f"  {display_name:<15} {c5_val:>12.4f} {gcb_val:>15.4f} {winner:>10}")

    print(f"  {'-'*55}")
    print(f"  {'Metrics won':<15} {scores['codet5']:>12} {scores['graphcodebert']:>15}")

    # Winner selection: Recall is the primary metric
    c5_recall = c5.get("recall", 0)
    gcb_recall = gcb.get("recall", 0)

    if c5_recall > gcb_recall:
        winner_key = "codet5"
        winner_name = "CodeT5"
        reason = f"Higher Recall ({c5_recall:.4f} vs {gcb_recall:.4f}) — the primary metric"
    elif gcb_recall > c5_recall:
        winner_key = "graphcodebert"
        winner_name = "GraphCodeBERT"
        reason = f"Higher Recall ({gcb_recall:.4f} vs {c5_recall:.4f}) — the primary metric"
    else:
        # Tie on recall → use F1 as tiebreaker
        c5_f1 = c5.get("f1", 0)
        gcb_f1 = gcb.get("f1", 0)
        if c5_f1 >= gcb_f1:
            winner_key = "codet5"
            winner_name = "CodeT5"
            reason = f"Tied on Recall; higher F1 ({c5_f1:.4f} vs {gcb_f1:.4f})"
        else:
            winner_key = "graphcodebert"
            winner_name = "GraphCodeBERT"
            reason = f"Tied on Recall; higher F1 ({gcb_f1:.4f} vs {c5_f1:.4f})"

    print(f"\n  🏆 WINNER: {winner_name}")
    print(f"     Reason: {reason}")
    print(f"     This backbone will be carried forward into Phase 2 & Phase 3.")

    # Copy winning model to phase1_winner/
    winner_src = os.path.join(MODELS_DIR, f"{winner_key}_binary_best")
    winner_dst = os.path.join(MODELS_DIR, "phase1_winner")
    if os.path.exists(winner_src):
        if os.path.exists(winner_dst):
            shutil.rmtree(winner_dst)
        shutil.copytree(winner_src, winner_dst)
        print(f"     Checkpoint copied to: {winner_dst}")

        # Write winner metadata
        winner_meta = {
            "winner": winner_key,
            "winner_name": winner_name,
            "reason": reason,
            "recall": c5_recall if winner_key == "codet5" else gcb_recall,
            "f1": c5.get("f1", 0) if winner_key == "codet5" else gcb.get("f1", 0),
            "auroc": c5.get("auroc", 0) if winner_key == "codet5" else gcb.get("auroc", 0),
            "timestamp": datetime.now().isoformat(),
        }
        with open(os.path.join(winner_dst, "winner_meta.json"), "w") as f:
            json.dump(winner_meta, f, indent=2)

    # Save comparison results
    comparison = {
        "codet5_metrics": c5,
        "graphcodebert_metrics": gcb,
        "winner": winner_key,
        "winner_name": winner_name,
        "selection_reason": reason,
        "timestamp": datetime.now().isoformat(),
    }
    comp_path = os.path.join(LOGS_DIR, "phase1_comparison.json")
    with open(comp_path, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"     Comparison saved to: {comp_path}")

    return comparison


# ─── Single-model evaluation ────────────────────────────────────────────────


def evaluate_single(model_key: str):
    """Re-evaluate a trained model on the test set and print results."""
    results = load_results(model_key)
    if results is None:
        return

    m = results["test_metrics"]
    print(f"\n{'='*50}")
    print(f"  {model_key.upper()} — Test Set Results")
    print(f"{'='*50}")
    print(f"  Recall:    {m['recall']:.4f}  ← primary metric")
    print(f"  Precision: {m['precision']:.4f}")
    print(f"  F1:        {m['f1']:.4f}")
    print(f"  AUROC:     {m['auroc']:.4f}")
    print(f"  Accuracy:  {m['accuracy']:.4f}")
    print(f"  Loss:      {m['loss']:.4f}")
    print(f"\n  Best epoch: {results['best_epoch']}")
    print(f"  LoRA used:  {results['use_lora']}")
    print(f"  Checkpoint: {results['checkpoint_dir']}")
    print(f"{'='*50}")


# ─── Quick prediction demo ──────────────────────────────────────────────────


def predict_snippet(model_key: str, code: str):
    """Run a quick prediction on a code snippet using a saved checkpoint.

    This demonstrates how to load and use the saved model for inference.
    """
    from src.data.dataset import get_tokenizer

    print(f"\n  Loading {model_key} for inference...")

    checkpoint_dir = os.path.join(MODELS_DIR, f"{model_key}_binary_best")
    config_path = os.path.join(checkpoint_dir, "training_config.json")

    if not os.path.exists(config_path):
        print(f"  ❌ Checkpoint not found at {checkpoint_dir}")
        return

    with open(config_path, "r") as f:
        config = json.load(f)

    # Load tokenizer
    tokenizer = get_tokenizer(model_key)

    # Load model
    device = torch.device("cpu")  # inference on CPU for simplicity
    use_lora = config.get("use_lora", False)

    if model_key == "codet5":
        from src.models.train_binary import CodeT5BinaryClassifier
        base_model = CodeT5BinaryClassifier("Salesforce/codet5-base")
    elif model_key == "graphcodebert":
        from transformers import AutoModelForSequenceClassification
        base_model = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/graphcodebert-base", num_labels=2,
        )

    if use_lora:
        from peft import PeftModel
        model = PeftModel.from_pretrained(base_model, checkpoint_dir)
    else:
        import torch as _torch
        base_model.load_state_dict(
            _torch.load(os.path.join(checkpoint_dir, "model.pt"),
                        map_location=device, weights_only=True)
        )
        model = base_model

    model = model.to(device)
    model.eval()

    # Tokenize
    inputs = tokenizer(
        code,
        max_length=config.get("max_length", 512),
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    ).to(device)

    # Predict
    with torch.no_grad():
        outputs = model(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
        )
        if isinstance(outputs, dict):
            logits = outputs["logits"]
        else:
            logits = outputs.logits

        probs = torch.softmax(logits, dim=-1)
        pred = probs.argmax(dim=-1).item()
        confidence = probs[0, pred].item()

    label = "VULNERABLE" if pred == 1 else "NON-VULNERABLE"

    print(f"\n  {'='*50}")
    print(f"  Code: {code[:80]}{'...' if len(code) > 80 else ''}")
    print(f"  Prediction:  {label}")
    print(f"  Confidence:  {confidence:.2%}")
    print(f"  P(vuln):     {probs[0, 1].item():.4f}")
    print(f"  P(non-vuln): {probs[0, 0].item():.4f}")
    print(f"  {'='*50}")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate and compare binary vulnerability detection models."
    )
    parser.add_argument(
        "--model", type=str, choices=["codet5", "graphcodebert"],
        help="Model to evaluate",
    )
    parser.add_argument(
        "--compare", action="store_true",
        help="Compare both models and select winner",
    )
    parser.add_argument(
        "--predict", action="store_true",
        help="Run quick prediction on a code snippet",
    )
    parser.add_argument(
        "--code", type=str,
        default='int main() { char buf[10]; gets(buf); return 0; }',
        help="Code snippet for --predict mode",
    )
    args = parser.parse_args()

    if args.compare:
        compare_models()
    elif args.predict and args.model:
        predict_snippet(args.model, args.code)
    elif args.model:
        evaluate_single(args.model)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
