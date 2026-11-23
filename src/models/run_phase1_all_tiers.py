"""
run_phase1_all_tiers.py — Orchestrator: train ALL Phase 1 models across all tiers.

Reads the Phase 0.5 manifest to discover available tiers, then trains
CodeT5 + GraphCodeBERT (+ VulBERTa for Tier 1) on each tier.

Usage:
    # Run everything (full pipeline)
    python src/models/run_phase1_all_tiers.py --bf16

    # Run only a specific tier
    python src/models/run_phase1_all_tiers.py --only-tier tier1_c_cpp --bf16

    # Run only a specific model
    python src/models/run_phase1_all_tiers.py --only-model codet5 --bf16

    # Dry run (show what would be trained without doing it)
    python src/models/run_phase1_all_tiers.py --dry-run
"""

import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

import sys
import json
import argparse
from datetime import datetime

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")


def load_manifest():
    manifest_path = os.path.join(PROCESSED_DIR, "manifest.json")
    if not os.path.exists(manifest_path):
        print(f"❌ Manifest not found: {manifest_path}")
        print("Run Phase 0.5 first: python src/data/audit_multilang.py")
        sys.exit(1)
    with open(manifest_path, "r") as f:
        return json.load(f)


def build_run_plan(manifest, only_tier=None, only_model=None):
    """Build the list of (tier, model, kwargs) training runs."""
    tiers = manifest.get("tier_assignments", {})
    splits = manifest.get("splits", {})

    runs = []

    # ── Tier 1 ───────────────────────────────────────────────────────────
    tier1_langs = tiers.get("tier1", [])
    if tier1_langs:
        # Find the tier1 key in splits
        tier1_key = None
        for k in splits:
            if k.startswith("tier1"):
                tier1_key = k
                break

        if tier1_key and (only_tier is None or only_tier == tier1_key):
            # CodeT5
            if only_model is None or only_model == "codet5":
                runs.append({
                    "tier": tier1_key, "model": "codet5",
                    "desc": f"Tier 1 CodeT5 ({tier1_langs})",
                    "kwargs": {},
                })

            # GraphCodeBERT
            if only_model is None or only_model == "graphcodebert":
                runs.append({
                    "tier": tier1_key, "model": "graphcodebert",
                    "desc": f"Tier 1 GraphCodeBERT ({tier1_langs})",
                    "kwargs": {},
                })

            # VulBERTa zero-shot (Tier 1 only)
            if only_model is None or only_model == "vulberta":
                runs.append({
                    "tier": tier1_key, "model": "vulberta",
                    "desc": f"Tier 1 VulBERTa zero-shot ({tier1_langs})",
                    "kwargs": {"zero_shot": True},
                })

                # VulBERTa fine-tuned (Tier 1 only)
                runs.append({
                    "tier": tier1_key, "model": "vulberta",
                    "desc": f"Tier 1 VulBERTa fine-tuned ({tier1_langs})",
                    "kwargs": {"epochs": 5},  # lighter training for VulBERTa
                })

    # ── Tier 2 (per-language, warm-started) ──────────────────────────────
    tier2_langs = tiers.get("tier2", [])
    tier1_winner_base = os.path.join(MODELS_DIR, "phase1_" + (tier1_key or "tier1_c_cpp") + "_codet5")

    for lang in tier2_langs:
        tier_key = f"tier2_{lang.lower().replace('+', 'p').replace('#', 'sharp')}"
        if tier_key not in splits:
            continue
        if only_tier is not None and only_tier != tier_key:
            continue

        # CodeT5 (warm-started from Tier 1)
        if only_model is None or only_model == "codet5":
            runs.append({
                "tier": tier_key, "model": "codet5",
                "desc": f"Tier 2 CodeT5 ({lang}, warm-started)",
                "kwargs": {"warm_start": tier1_winner_base},
            })

        # GraphCodeBERT (warm-started from Tier 1)
        if only_model is None or only_model == "graphcodebert":
            gcb_base = os.path.join(MODELS_DIR, "phase1_" + (tier1_key or "tier1_c_cpp") + "_graphcodebert")
            runs.append({
                "tier": tier_key, "model": "graphcodebert",
                "desc": f"Tier 2 GraphCodeBERT ({lang}, warm-started)",
                "kwargs": {"warm_start": gcb_base},
            })

    # ── Tier 3 (shared model) ────────────────────────────────────────────
    tier3_langs = tiers.get("tier3", [])
    if tier3_langs and (only_tier is None or only_tier == "tier3_shared"):
        if "tier3_shared" in splits:
            if only_model is None or only_model == "codet5":
                runs.append({
                    "tier": "tier3_shared", "model": "codet5",
                    "desc": f"Tier 3 CodeT5 shared ({tier3_langs})",
                    "kwargs": {},
                })

            if only_model is None or only_model == "graphcodebert":
                runs.append({
                    "tier": "tier3_shared", "model": "graphcodebert",
                    "desc": f"Tier 3 GraphCodeBERT shared ({tier3_langs})",
                    "kwargs": {},
                })

    return runs


def main():
    parser = argparse.ArgumentParser(
        description="Orchestrate all Phase 1 training runs across tiers."
    )
    parser.add_argument("--only-tier", type=str, default=None,
                        help="Train only this tier")
    parser.add_argument("--only-model", type=str, default=None,
                        choices=["codet5", "graphcodebert", "vulberta"],
                        help="Train only this model")
    parser.add_argument("--bf16", action="store_true",
                        help="Use bfloat16 (CUDA only)")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without executing")
    args = parser.parse_args()

    manifest = load_manifest()
    runs = build_run_plan(manifest, args.only_tier, args.only_model)

    print(f"\n{'='*70}")
    print(f"  PHASE 1 (REVISED) — ALL-TIER ORCHESTRATOR")
    print(f"  Total runs planned: {len(runs)}")
    print(f"{'='*70}")

    for i, run in enumerate(runs, 1):
        print(f"\n  [{i}/{len(runs)}] {run['desc']}")
        print(f"         tier={run['tier']}, model={run['model']}")
        if run['kwargs']:
            print(f"         extra: {run['kwargs']}")

    if args.dry_run:
        print(f"\n  🏁 Dry run complete. {len(runs)} runs would be executed.")
        return

    print(f"\n{'─'*70}")
    print(f"  Starting training runs...")
    print(f"{'─'*70}")

    from src.models.train_binary_v2 import train_v2

    completed = []
    failed = []

    for i, run in enumerate(runs, 1):
        print(f"\n{'━'*70}")
        print(f"  RUN {i}/{len(runs)}: {run['desc']}")
        print(f"{'━'*70}")

        try:
            kwargs = {
                "model_key": run["model"],
                "tier": run["tier"],
                "epochs": args.epochs,
                "batch_size": args.batch_size,
                "use_bf16": args.bf16,
                **run["kwargs"],
            }
            result = train_v2(**kwargs)
            completed.append({
                "run": run["desc"],
                "tier": run["tier"],
                "model": run["model"],
                "recall": result.get("test_metrics_optimal", {}).get("recall", 0),
                "f1": result.get("test_metrics_optimal", {}).get("f1", 0),
            })
        except Exception as e:
            print(f"\n  ❌ FAILED: {e}")
            failed.append({"run": run["desc"], "error": str(e)})

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  PHASE 1 ORCHESTRATOR — COMPLETE")
    print(f"{'='*70}")
    print(f"  Completed: {len(completed)} / {len(runs)}")
    print(f"  Failed:    {len(failed)} / {len(runs)}")

    if completed:
        print(f"\n  Completed runs:")
        for c in completed:
            print(f"    ✅ {c['run']} — Recall={c['recall']:.4f}, F1={c['f1']:.4f}")

    if failed:
        print(f"\n  Failed runs:")
        for f in failed:
            print(f"    ❌ {f['run']} — {f['error']}")

    # Run winner selection
    print(f"\n  Running winner selection...")
    from src.evaluation.evaluate_binary_v2 import select_winners, compare_all
    compare_all()
    select_winners()

    # Save orchestration log
    log = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": len(runs),
        "completed": completed,
        "failed": failed,
    }
    log_path = os.path.join(LOGS_DIR, "phase1_orchestration_v2.json")
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"\n  Orchestration log: {log_path}")


if __name__ == "__main__":
    main()
