"""
evaluate_severity.py — Phase 3: Evaluation & Comparison for CVSS Severity Scoring.

Loads all Phase 3 result JSONs and prints:
  - Consolidated comparison table (Approach A vs B vs C, per tier)
  - Per-band CVSS breakdown (Low / Medium / High / Critical)
  - Per-tier vs shared comparison
  - Winner selection and export

Usage:
    python src/evaluation/evaluate_severity.py --compare-all
    python src/evaluation/evaluate_severity.py --tier tier1_c_cpp
    python src/evaluation/evaluate_severity.py --select-winners
    python src/evaluation/evaluate_severity.py --per-tier-vs-shared
"""

import os
import sys
import json
import glob
import argparse
from datetime import datetime

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")


def load_all_phase3_results():
    """Load all Phase 3 result JSONs."""
    results = {}
    for f in sorted(glob.glob(os.path.join(LOGS_DIR, "phase3_severity_results_*.json"))):
        key = os.path.basename(f).replace("phase3_severity_results_", "").replace(".json", "")
        with open(f) as fp:
            results[key] = json.load(fp)
    return results


def print_consolidated_table(results):
    """Print the authoritative cross-tier severity comparison table."""
    print("=" * 100)
    print("  PHASE 3 — CVSS SEVERITY SCORING: CONSOLIDATED COMPARISON TABLE")
    print("=" * 100)

    if not results:
        print("  No Phase 3 results found.")
        return

    print(f"\n  {'Approach':^10} | {'Tier':^16} | {'Model':^16} | {'MAE':>7} | {'RMSE':>7} "
          f"| {'R²':>6} | {'Pearson':>8} | {'Band Acc':>8} | {'N':>5}")
    print("  " + "-" * 95)

    for key, data in sorted(results.items()):
        m = data.get("test_metrics", {})
        approach = data.get("approach", "?")
        tier = data.get("tier", "?")
        model = data.get("model_key", "?")
        mae = m.get("mae", 0)
        rmse = m.get("rmse", 0)
        r2 = m.get("r2", 0)
        pearson = m.get("pearson", 0)
        band_acc = m.get("band_accuracy", 0)
        n = m.get("n_samples", 0)
        print(f"  {approach:^10} | {tier:^16} | {model:^16} | {mae:>7.4f} | {rmse:>7.4f} "
              f"| {r2:>6.4f} | {pearson:>8.4f} | {band_acc:>8.4f} | {n:>5}")


def print_tier_breakdown(tier, results):
    """Print per-band CVSS breakdown for a specific tier."""
    print("\n" + "=" * 80)
    print(f"  DETAILED PER-BAND BREAKDOWN FOR: {tier.upper()}")
    print("=" * 80)

    tier_results = {k: v for k, v in results.items()
                    if v.get("tier") == tier}

    if not tier_results:
        print(f"  ⚠️  No results found for {tier}.")
        return

    for key, data in sorted(tier_results.items()):
        approach = data.get("approach", "?")
        model = data.get("model_key", "?")
        m = data.get("test_metrics", {})
        pb = data.get("per_band_metrics", {})

        print(f"\n  [{approach}] {model} — MAE={m.get('mae', 0):.4f}, RMSE={m.get('rmse', 0):.4f}")
        print(f"  {'Band':>20} | {'MAE':>7} | {'RMSE':>7} | {'Count':>6}")
        print("  " + "-" * 50)

        for band in ["Low (0-3.9)", "Medium (4-6.9)", "High (7-8.9)", "Critical (9-10)"]:
            b = pb.get(band, {})
            b_mae = b.get("mae", 0)
            b_rmse = b.get("rmse", 0)
            count = b.get("count", 0)
            print(f"  {band:>20} | {b_mae:>7.4f} | {b_rmse:>7.4f} | {count:>6}")


def print_per_tier_vs_shared(results):
    """Compare per-tier models vs the shared cross-tier model."""
    print("\n" + "=" * 90)
    print("  PER-TIER vs SHARED SEVERITY MODEL COMPARISON")
    print("  (Central research question: does CVSS severity benefit from per-tier training?)")
    print("=" * 90)

    # Find shared model results (Approach C)
    shared_results = {k: v for k, v in results.items() if v.get("approach") == "C"}
    per_tier_results = {k: v for k, v in results.items() if v.get("approach") in ["A", "B"]}

    if not shared_results:
        print("  ⚠️  No Approach C (shared) results found.")
        return

    # Get tiers that have per-tier results
    tiers_with_data = set()
    for k, v in per_tier_results.items():
        tiers_with_data.add(v.get("tier"))

    print(f"\n  {'Tier':^16} | {'Per-Tier MAE':>13} | {'Shared MAE':>11} | {'Winner':^10} | {'Delta':>8}")
    print("  " + "-" * 70)

    for tier in sorted(tiers_with_data):
        # Best per-tier
        best_per_tier = None
        for k, v in per_tier_results.items():
            if v.get("tier") == tier:
                mae = v.get("test_metrics", {}).get("mae", float("inf"))
                if best_per_tier is None or mae < best_per_tier["mae"]:
                    best_per_tier = {"mae": mae, "approach": v.get("approach"),
                                     "model": v.get("model_key")}

        # Best shared (evaluated on same tier's test split would need re-eval)
        best_shared = None
        for k, v in shared_results.items():
            mae = v.get("test_metrics", {}).get("mae", float("inf"))
            if best_shared is None or mae < best_shared["mae"]:
                best_shared = {"mae": mae, "model": v.get("model_key")}

        if best_per_tier and best_shared:
            winner = "Per-Tier" if best_per_tier["mae"] < best_shared["mae"] else "Shared"
            delta = best_shared["mae"] - best_per_tier["mae"]
            print(f"  {tier:^16} | {best_per_tier['mae']:>13.4f} | {best_shared['mae']:>11.4f} "
                  f"| {winner:^10} | {delta:>+8.4f}")

    print("\n  Note: Positive delta means per-tier is better (lower MAE).")
    print("  CVSS severity reflects exploitability/impact, which is less syntax-dependent")
    print("  than vulnerability type (CWE). A shared model may generalize better.")


def select_winners(results):
    """Select winning severity models per tier and export."""
    print("\n" + "=" * 70)
    print("  SELECTING & EXPORTING PHASE 3 WINNERS PER TIER")
    print("=" * 70)

    # Find best per tier (across all approaches)
    tier_best = {}
    for key, data in results.items():
        tier = data.get("tier", "?")
        mae = data.get("test_metrics", {}).get("mae", float("inf"))
        if tier not in tier_best or mae < tier_best[tier]["mae"]:
            tier_best[tier] = {
                "key": key,
                "mae": mae,
                "approach": data.get("approach"),
                "model": data.get("model_key"),
                "rmse": data.get("test_metrics", {}).get("rmse", 0),
                "r2": data.get("test_metrics", {}).get("r2", 0),
                "pearson": data.get("test_metrics", {}).get("pearson", 0),
                "band_accuracy": data.get("test_metrics", {}).get("band_accuracy", 0),
            }

    winners_meta = {}
    for tier, info in sorted(tier_best.items()):
        dest_dir = os.path.join(MODELS_DIR, f"phase3_winner_{tier}")
        os.makedirs(dest_dir, exist_ok=True)
        meta = {
            "tier": tier,
            "winner_approach": info["approach"],
            "winner_model": info["model"],
            "mae": info["mae"],
            "rmse": info["rmse"],
            "r2": info["r2"],
            "pearson": info["pearson"],
            "band_accuracy": info["band_accuracy"],
            "timestamp": datetime.now().isoformat(),
        }
        with open(os.path.join(dest_dir, "winner_metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)
        winners_meta[tier] = meta
        print(f"  🏆 [{tier}] Approach {info['approach']} {info['model']}: "
              f"MAE={info['mae']:.4f}, RMSE={info['rmse']:.4f}")
        print(f"     Saved to: {dest_dir}")

    summary_path = os.path.join(LOGS_DIR, "phase3_winners.json")
    with open(summary_path, "w") as f:
        json.dump(winners_meta, f, indent=2)
    print(f"\n  Consolidated winners written to: {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Phase 3 CVSS Severity Scoring.")
    parser.add_argument("--compare-all", action="store_true",
                        help="Print consolidated comparison table")
    parser.add_argument("--tier", type=str, default=None,
                        help="Detailed per-band breakdown for a tier")
    parser.add_argument("--select-winners", action="store_true",
                        help="Export winning models per tier")
    parser.add_argument("--per-tier-vs-shared", action="store_true",
                        help="Compare per-tier vs shared model")
    args = parser.parse_args()

    results = load_all_phase3_results()

    if args.tier:
        print_tier_breakdown(args.tier, results)
        return

    if args.select_winners:
        select_winners(results)
        return

    if args.per_tier_vs_shared:
        print_per_tier_vs_shared(results)
        return

    # Default: show comparison table
    print_consolidated_table(results)
    if args.compare_all:
        for tier in ["tier1_c_cpp", "tier2_cpp", "tier2_python", "tier2_php",
                      "tier3_shared", "all_shared"]:
            print_tier_breakdown(tier, results)
        print_per_tier_vs_shared(results)


if __name__ == "__main__":
    main()
