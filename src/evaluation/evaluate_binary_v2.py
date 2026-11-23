"""
evaluate_binary_v2.py — Phase 1 (Revised): Multi-tier evaluation & winner selection.

Supports:
  1. Evaluating a single tier/model result
  2. Consolidated comparison table across ALL tiers and models
  3. Per-tier winner selection → copies to models/saved/phase1_winner_<tier>/
  4. Per-tier threshold sweep display

Usage:
    # Show results for one tier/model
    python src/evaluation/evaluate_binary_v2.py --tier tier1_c_cpp --model codet5

    # Consolidated comparison across all trained models
    python src/evaluation/evaluate_binary_v2.py --compare-all

    # Select per-tier winners and copy checkpoints
    python src/evaluation/evaluate_binary_v2.py --select-winners
"""

import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

import sys
import json
import glob
import shutil
import argparse
from datetime import datetime
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


# ─── Result loading ─────────────────────────────────────────────────────────


def find_all_results() -> List[Dict]:
    """Find all Phase 1 v2 result JSON files."""
    pattern = os.path.join(LOGS_DIR, "phase1_*_results_v2.json")
    zs_pattern = os.path.join(LOGS_DIR, "phase1_*_zeroshot.json")

    results = []
    for path in sorted(glob.glob(pattern) + glob.glob(zs_pattern)):
        with open(path, "r") as f:
            data = json.load(f)
        data["_results_file"] = path
        results.append(data)

    return results


def load_single_result(tier: str, model: str) -> Optional[Dict]:
    """Load result for a specific tier/model combo."""
    candidates = [
        os.path.join(LOGS_DIR, f"phase1_{tier}_{model}_results_v2.json"),
        os.path.join(LOGS_DIR, f"phase1_{tier}_{model}_zeroshot.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    return None


# ─── Single result display ──────────────────────────────────────────────────


def display_single(tier: str, model: str):
    """Display detailed results for a single tier/model."""
    result = load_single_result(tier, model)
    if result is None:
        print(f"\n  ❌ No results found for {tier}/{model}.")
        print(f"  Run training first: python src/models/train_binary_v2.py --model {model} --tier {tier}")
        return

    mode = result.get("mode", "trained")
    metrics = result.get("test_metrics_optimal") or result.get("test_metrics_default") or result.get("test_metrics", {})
    best_t = result.get("best_threshold", 0.5)

    print(f"\n{'='*60}")
    print(f"  {model.upper()} on {tier} ({mode})")
    print(f"{'='*60}")
    print(f"  Recall:    {metrics.get('recall', 0):.4f}  ← primary metric")
    print(f"  Precision: {metrics.get('precision', 0):.4f}")
    print(f"  F1:        {metrics.get('f1', 0):.4f}")
    print(f"  AUROC:     {metrics.get('auroc', 0):.4f}")
    print(f"  Accuracy:  {metrics.get('accuracy', 0):.4f}")
    print(f"  Threshold: {best_t}")

    if mode == "trained":
        print(f"\n  Best epoch:  {result.get('best_epoch', '?')}")
        print(f"  Best val F1: {result.get('best_val_f1', '?'):.4f}")
        print(f"  Checkpoint:  {result.get('checkpoint_dir', '?')}")

    # Show threshold sweep
    sweep = result.get("threshold_sweep", [])
    if sweep:
        print(f"\n  Threshold Sweep:")
        print(f"  {'Threshold':>10} {'Recall':>8} {'Precision':>10} {'F1':>8} {'Floor?':>7}")
        print(f"  {'─'*45}")
        for row in sweep:
            marker = " ◀" if row["threshold"] == best_t else ""
            floor = "✓" if row.get("meets_floor", False) else "✗"
            print(f"  {row['threshold']:>10.2f} {row['recall']:>8.4f} "
                  f"{row['precision']:>10.4f} {row['f1']:>8.4f} {floor:>7}{marker}")

    hp = result.get("hyperparams", {})
    if hp:
        print(f"\n  Hyperparameters:")
        for k, v in hp.items():
            print(f"    {k}: {v}")

    print(f"{'='*60}")


# ─── Consolidated comparison ────────────────────────────────────────────────


def compare_all():
    """Print a consolidated comparison table across all tiers and models."""
    all_results = find_all_results()

    if not all_results:
        print("\n  ❌ No Phase 1 v2 results found.")
        print("  Train models first: python src/models/train_binary_v2.py ...")
        return

    print(f"\n{'='*90}")
    print(f"  PHASE 1 (REVISED) — CONSOLIDATED RESULTS")
    print(f"{'='*90}")

    print(f"\n  {'Tier':<20} {'Model':<15} {'Mode':<10} {'Recall':>8} {'Prec':>8} "
          f"{'F1':>8} {'AUROC':>8} {'Acc':>8} {'Thr':>5}")
    print(f"  {'─'*100}")

    # Group by tier
    by_tier = {}
    for r in all_results:
        tier = r.get("tier", "unknown")
        if tier not in by_tier:
            by_tier[tier] = []
        by_tier[tier].append(r)

    for tier in sorted(by_tier.keys()):
        for r in by_tier[tier]:
            model = r.get("model", "?")
            mode = r.get("mode", "trained")[:8]
            metrics = r.get("test_metrics_optimal") or r.get("test_metrics_default") or r.get("test_metrics", {})
            best_t = r.get("best_threshold", 0.5)

            print(f"  {tier:<20} {model:<15} {mode:<10} "
                  f"{metrics.get('recall', 0):>8.4f} "
                  f"{metrics.get('precision', 0):>8.4f} "
                  f"{metrics.get('f1', 0):>8.4f} "
                  f"{metrics.get('auroc', 0):>8.4f} "
                  f"{metrics.get('accuracy', 0):>8.4f} "
                  f"{best_t:>5.2f}")

    print(f"\n  Total models evaluated: {len(all_results)}")


# ─── Per-tier winner selection ───────────────────────────────────────────────


def select_winners():
    """Select the best model per tier and copy to phase1_winner_<tier>/."""
    all_results = find_all_results()

    if not all_results:
        print("\n  ❌ No results found.")
        return

    # Group by tier
    by_tier = {}
    for r in all_results:
        tier = r.get("tier", "unknown")
        if tier not in by_tier:
            by_tier[tier] = []
        by_tier[tier].append(r)

    print(f"\n{'='*70}")
    print(f"  PHASE 1 — PER-TIER WINNER SELECTION")
    print(f"{'='*70}")

    winners = {}

    for tier in sorted(by_tier.keys()):
        candidates = by_tier[tier]

        # Select by: highest Recall (primary metric), then F1 as tiebreaker
        # Only consider trained models (not zero-shot) unless no trained exists
        trained = [r for r in candidates if r.get("mode") == "trained"]
        pool = trained if trained else candidates

        best = None
        best_recall = -1
        best_f1 = -1

        for r in pool:
            metrics = r.get("test_metrics_optimal") or r.get("test_metrics_default") or r.get("test_metrics", {})
            rec = metrics.get("recall", 0)
            f1 = metrics.get("f1", 0)

            if rec > best_recall or (rec == best_recall and f1 > best_f1):
                best_recall = rec
                best_f1 = f1
                best = r

        if best is None:
            print(f"\n  {tier}: ❌ No valid candidates")
            continue

        model = best.get("model", "?")
        mode = best.get("mode", "?")
        metrics = best.get("test_metrics_optimal") or best.get("test_metrics_default") or best.get("test_metrics", {})
        best_t = best.get("best_threshold", 0.5)

        print(f"\n  🏆 {tier}: {model} ({mode})")
        print(f"     Recall={metrics.get('recall', 0):.4f}, F1={metrics.get('f1', 0):.4f}, "
              f"AUROC={metrics.get('auroc', 0):.4f}, Threshold={best_t}")

        # Copy checkpoint to winner directory
        src_dir = best.get("checkpoint_dir")
        if src_dir and os.path.isdir(src_dir):
            dst_dir = os.path.join(MODELS_DIR, f"phase1_winner_{tier}")
            if os.path.exists(dst_dir):
                shutil.rmtree(dst_dir)
            shutil.copytree(src_dir, dst_dir)

            # Write winner metadata
            winner_meta = {
                "tier": tier, "winner_model": model, "mode": mode,
                "recall": metrics.get("recall", 0),
                "precision": metrics.get("precision", 0),
                "f1": metrics.get("f1", 0),
                "auroc": metrics.get("auroc", 0),
                "best_threshold": best_t,
                "source_checkpoint": src_dir,
                "timestamp": datetime.now().isoformat(),
            }
            with open(os.path.join(dst_dir, "winner_meta.json"), "w") as f:
                json.dump(winner_meta, f, indent=2)

            print(f"     Saved to: {dst_dir}")
        else:
            print(f"     ⚠️ No checkpoint directory found to copy")

        winners[tier] = {
            "model": model, "mode": mode,
            "recall": metrics.get("recall", 0),
            "f1": metrics.get("f1", 0),
            "threshold": best_t,
        }

    # Save consolidated winners
    winners_path = os.path.join(LOGS_DIR, "phase1_winners_v2.json")
    with open(winners_path, "w") as f:
        json.dump(winners, f, indent=2)
    print(f"\n  Winners summary: {winners_path}")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Phase 1 (Revised): Multi-tier evaluation and winner selection."
    )
    parser.add_argument("--tier", type=str, help="Tier to evaluate")
    parser.add_argument("--model", type=str, help="Model to evaluate")
    parser.add_argument(
        "--compare-all", action="store_true",
        help="Show consolidated comparison across all tiers/models",
    )
    parser.add_argument(
        "--select-winners", action="store_true",
        help="Select per-tier winners and copy to phase1_winner_<tier>/",
    )
    args = parser.parse_args()

    if args.compare_all:
        compare_all()
    elif args.select_winners:
        select_winners()
    elif args.tier and args.model:
        display_single(args.tier, args.model)
    else:
        # Default: show all results
        compare_all()


if __name__ == "__main__":
    main()
