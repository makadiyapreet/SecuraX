"""
evaluate_cwe.py — Phase 2 (v2) CWE classification evaluation.

Supports:
  1. --evaluate: Show test set results for any trained variant
  2. --predict: CWE inference on a code snippet
  3. --compare-v1: Show v1 vs v2 comparison table

Usage:
    python src/evaluation/evaluate_cwe.py --evaluate --model codet5 --variant-tag v2
    python src/evaluation/evaluate_cwe.py --predict --code "..."
    python src/evaluation/evaluate_cwe.py --compare-v1
"""

import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

import sys
import json
import argparse
from typing import Dict, Optional

import numpy as np
import torch

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


# ─── Evaluate ────────────────────────────────────────────────────────────────


def evaluate(model_key="codet5", variant_tag="v2"):
    """Display saved CWE model evaluation results."""
    tag = f"{model_key}_cwe_{variant_tag}"
    results_path = os.path.join(LOGS_DIR, f"phase2_cwe_results_{tag}.json")

    if not os.path.exists(results_path):
        print(f"  ⚠️  Results not found: {results_path}")
        print(f"  Run training first:")
        print(f"    python src/models/train_cwe.py --model {model_key} --variant-tag {variant_tag}")
        return

    with open(results_path, "r") as f:
        results = json.load(f)

    m = results["test_metrics"]
    class_names = results["class_names"]
    cm = np.array(results["confusion_matrix"])

    print(f"\n{'='*60}")
    print(f"  PHASE 2 ({variant_tag}) — {model_key.upper()} CWE RESULTS")
    print(f"{'='*60}")
    print(f"  Classes:        {results['num_classes']}")
    print(f"  Best epoch:     {results.get('best_epoch', '?')}")
    print(f"  LoRA:           {results.get('use_lora', '?')}")
    print(f"  Focal Loss γ:   {results.get('focal_gamma', '?')}")
    print(f"  Oversampling:   {results.get('use_oversampling', '?')}")

    print(f"\n  Macro-Recall:   {m['macro_recall']:.4f}")
    print(f"  Macro-F1:       {m['macro_f1']:.4f}")
    print(f"  Weighted-F1:    {m['weighted_f1']:.4f}")
    print(f"  Accuracy:       {m['accuracy']:.4f}")
    if "loss" in m:
        print(f"  Loss:           {m['loss']:.4f}")

    # Per-class table
    print(f"\n  {'Class':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-'*60}")

    per_class = results.get("per_class_report", {})
    for name in class_names:
        if name in per_class:
            r = per_class[name]
            print(f"  {name:<20} {r['precision']:>10.4f} {r['recall']:>10.4f} "
                  f"{r['f1-score']:>10.4f} {int(r['support']):>10}")

    print(f"  {'-'*60}")
    macro = results.get("macro_avg", {})
    if macro:
        print(f"  {'macro avg':<20} {macro.get('precision',0):>10.4f} "
              f"{macro.get('recall',0):>10.4f} {macro.get('f1-score',0):>10.4f}")
    weighted = results.get("weighted_avg", {})
    if weighted:
        print(f"  {'weighted avg':<20} {weighted.get('precision',0):>10.4f} "
              f"{weighted.get('recall',0):>10.4f} {weighted.get('f1-score',0):>10.4f}")

    # Confusion matrix diagonal
    print(f"\n  Diagonal (correct predictions per class):")
    for i, name in enumerate(class_names):
        if i < cm.shape[0]:
            total = cm[i].sum()
            correct = cm[i][i] if i < cm.shape[1] else 0
            pct = correct / total * 100 if total > 0 else 0
            print(f"    {name:<20} {correct:>4}/{total:<4}  ({pct:.1f}%)")

    # Worst classes
    worst = results.get("worst_classes", [])
    if worst:
        print(f"\n  Worst-performing classes:")
        for w in worst[:3]:
            print(f"    {w['name']:<20} F1={w['f1']:.4f}  support={w['support']}")

    print(f"{'='*60}\n")


# ─── V1 vs V2 comparison ────────────────────────────────────────────────────


def compare_v1(variant_tag="v2"):
    """Show comparison table between v1 baseline and all v2 variants."""
    from src.models.train_cwe import compare_v1_v2
    compare_v1_v2(variant_tag)


# ─── Prediction ──────────────────────────────────────────────────────────────


def predict_cwe(code: str, model_key="codet5", variant_tag="v2"):
    """Predict CWE class for a code snippet."""
    from src.data.dataset import get_tokenizer

    checkpoint_dir = os.path.join(MODELS_DIR, f"{model_key}_cwe_{variant_tag}_best")
    config_path = os.path.join(checkpoint_dir, "training_config.json")

    if not os.path.exists(config_path):
        print(f"  ❌ Checkpoint not found: {checkpoint_dir}")
        print(f"  Run training first.")
        return

    with open(config_path, "r") as f:
        config = json.load(f)

    num_classes = config["num_classes"]
    class_names = config["class_names"]
    use_lora = config.get("use_lora", False)

    tokenizer = get_tokenizer(model_key)
    device = torch.device("cpu")

    # Load model
    from src.models.train_cwe import CodeT5CWEClassifier, GraphCodeBERTCWEClassifier

    if model_key == "codet5":
        base_model = CodeT5CWEClassifier("Salesforce/codet5-base", num_classes)
    else:
        base_model = GraphCodeBERTCWEClassifier("microsoft/graphcodebert-base", num_classes)

    if use_lora:
        from peft import PeftModel
        model = PeftModel.from_pretrained(base_model, checkpoint_dir)
    else:
        base_model.load_state_dict(torch.load(
            os.path.join(checkpoint_dir, "model.pt"),
            map_location=device, weights_only=True
        ))
        model = base_model

    model = model.to(device)
    model.eval()

    inputs = tokenizer(
        code,
        max_length=config.get("max_length", 512),
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    ).to(device)

    with torch.no_grad():
        outputs = model(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
        )
        logits = outputs.logits
        probs = torch.softmax(logits, dim=-1)
        top5 = probs[0].topk(5)

    print(f"\n  {'='*55}")
    print(f"  Code: {code[:80]}{'...' if len(code) > 80 else ''}")
    print(f"\n  Top-5 CWE Group Predictions:")
    for i, (prob, idx) in enumerate(zip(top5.values, top5.indices)):
        name = class_names[idx.item()] if idx.item() < len(class_names) else "?"
        print(f"    {i+1}. {name:<20} {prob.item():.2%}")
    print(f"  {'='*55}")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2 CWE classification evaluation."
    )
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--predict", action="store_true")
    parser.add_argument("--compare-v1", action="store_true")
    parser.add_argument("--model", type=str, default="codet5",
                        choices=["codet5", "graphcodebert", "ensemble"])
    parser.add_argument("--variant-tag", type=str, default="v2")
    parser.add_argument("--code", type=str,
                        default='int main() { char buf[10]; gets(buf); return 0; }')
    args = parser.parse_args()

    if args.evaluate:
        if args.model == "ensemble":
            # Show ensemble results
            tag = f"ensemble_{args.variant_tag}"
            results_path = os.path.join(LOGS_DIR, f"phase2_cwe_results_{tag}.json")
            if os.path.exists(results_path):
                # Reuse evaluate with a small wrapper
                with open(results_path) as f:
                    r = json.load(f)
                m = r["test_metrics"]
                print(f"\n  ENSEMBLE RESULTS:")
                print(f"    Macro-Recall: {m['macro_recall']:.4f}")
                print(f"    Macro-F1:     {m['macro_f1']:.4f}")
                print(f"    Accuracy:     {m['accuracy']:.4f}")
            else:
                print(f"  Run ensemble first: python src/models/train_cwe.py --ensemble")
        else:
            evaluate(args.model, args.variant_tag)
    elif args.predict:
        predict_cwe(args.code, args.model, args.variant_tag)
    elif args.compare_v1:
        compare_v1(args.variant_tag)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
