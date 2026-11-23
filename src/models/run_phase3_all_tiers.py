"""
run_phase3_all_tiers.py — Orchestrator for Phase 3 Multi-Tier Severity Scoring.

Schedules and executes all Approach A/B/C severity training runs across tiers.

Usage:
    # Dry run — see what will be trained
    python src/models/run_phase3_all_tiers.py --dry-run

    # Full execution on CUDA
    python src/models/run_phase3_all_tiers.py --bf16

    # Specific approach only
    python src/models/run_phase3_all_tiers.py --only-approach A --bf16
    python src/models/run_phase3_all_tiers.py --only-approach C --bf16

    # Specific tier only
    python src/models/run_phase3_all_tiers.py --only-tier tier1_c_cpp --bf16
"""

import os
import sys
import subprocess
import argparse

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")


def build_phase3_run_plan(only_approach=None, only_tier=None, only_model=None):
    """Build a list of Phase 3 training runs.

    Returns:
        list of dicts with 'approach', 'tier', 'model', 'desc', 'args'
    """
    runs = []

    # Warm-start checkpoints (from Phase 1 winners)
    warm_start_t1 = os.path.join(MODELS_DIR, "phase1_winner_tier1_c_cpp")

    # ── Approach A: Single-task severity regression per tier ────────────
    if only_approach is None or only_approach == "A":
        approach_a_configs = [
            # Tier 1: Fine-tune on Tier 1 severity data
            ("tier1_c_cpp", "codet5", "Tier 1 C/C++ CodeT5 Severity", []),
            ("tier1_c_cpp", "graphcodebert", "Tier 1 C/C++ GraphCodeBERT Severity", []),
            # Tier 2: Warm-started from Tier 1
            ("tier2_cpp", "graphcodebert", "Tier 2 C++ GraphCodeBERT Severity (warm)",
             ["--warm-start", warm_start_t1]),
            ("tier2_python", "graphcodebert", "Tier 2 Python GraphCodeBERT Severity (warm)",
             ["--warm-start", warm_start_t1]),
            ("tier2_php", "codet5", "Tier 2 PHP CodeT5 Severity (warm)",
             ["--warm-start", warm_start_t1]),
            # Tier 3: With language tokens
            ("tier3_shared", "codet5", "Tier 3 Shared CodeT5 Severity (<LANG=xx>)",
             ["--use-lang-tokens"]),
        ]

        for tier, model, desc, extra_args in approach_a_configs:
            if only_tier is None or only_tier == tier:
                if only_model is None or only_model == model:
                    runs.append({
                        "approach": "A", "tier": tier, "model": model,
                        "desc": f"[A] {desc}",
                        "args": ["--approach", "A", "--model", model, "--tier", tier] + extra_args,
                    })

    # ── Approach B: Multi-task per tier (VF + CWE + Severity) ──────────
    if only_approach is None or only_approach == "B":
        approach_b_configs = [
            ("tier1_c_cpp", "graphcodebert", "Tier 1 C/C++ GraphCodeBERT Multi-Task", []),
            ("tier2_cpp", "graphcodebert", "Tier 2 C++ GraphCodeBERT Multi-Task",
             ["--warm-start", warm_start_t1]),
            ("tier2_php", "codet5", "Tier 2 PHP CodeT5 Multi-Task",
             ["--warm-start", warm_start_t1]),
            ("tier3_shared", "codet5", "Tier 3 Shared CodeT5 Multi-Task",
             ["--use-lang-tokens"]),
        ]

        for tier, model, desc, extra_args in approach_b_configs:
            if only_tier is None or only_tier == tier:
                if only_model is None or only_model == model:
                    runs.append({
                        "approach": "B", "tier": tier, "model": model,
                        "desc": f"[B] {desc}",
                        "args": ["--approach", "B", "--model", model, "--tier", tier] + extra_args,
                    })

    # ── Approach C: ONE shared severity regressor across all tiers ─────
    if only_approach is None or only_approach == "C":
        if only_tier is None:  # Approach C doesn't use per-tier
            if only_model is None or only_model == "codet5":
                runs.append({
                    "approach": "C", "tier": "all_shared", "model": "codet5",
                    "desc": "[C] Shared CodeT5 Severity (all tiers, <LANG=xx>)",
                    "args": ["--approach", "C", "--model", "codet5"],
                })
            if only_model is None or only_model == "graphcodebert":
                runs.append({
                    "approach": "C", "tier": "all_shared", "model": "graphcodebert",
                    "desc": "[C] Shared GraphCodeBERT Severity (all tiers, <LANG=xx>)",
                    "args": ["--approach", "C", "--model", "graphcodebert"],
                })

    return runs


def main():
    parser = argparse.ArgumentParser(description="Run Phase 3 multi-tier severity pipeline.")
    parser.add_argument("--only-approach", type=str, default=None, choices=["A", "B", "C"])
    parser.add_argument("--only-tier", type=str, default=None,
                        choices=["tier1_c_cpp", "tier2_cpp", "tier2_python", "tier2_php", "tier3_shared"])
    parser.add_argument("--only-model", type=str, default=None, choices=["codet5", "graphcodebert"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--bf16", action="store_true")
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--max-samples", type=int, default=None)
    args = parser.parse_args()

    runs = build_phase3_run_plan(args.only_approach, args.only_tier, args.only_model)

    print("=" * 70)
    print("  PHASE 3 MULTI-TIER SEVERITY SCORING EXECUTION PLAN")
    print(f"  Total Scheduled Runs: {len(runs)}")
    print("=" * 70)

    for i, r in enumerate(runs, 1):
        extra = []
        if args.bf16:
            extra.append("--bf16")
        if args.max_samples:
            extra.extend(["--max-samples", str(args.max_samples)])
        extra.extend(["--epochs", str(args.epochs)])
        cmd = [sys.executable, "src/models/train_severity.py"] + r["args"] + extra
        print(f"\n[{i}/{len(runs)}] {r['desc']}")
        print(f"  Command: {' '.join(cmd)}")

    if args.dry_run:
        print("\n✅ Dry run completed successfully.")
        return

    # Execute runs
    for i, r in enumerate(runs, 1):
        print("\n" + "#" * 70)
        print(f"  Executing [{i}/{len(runs)}]: {r['desc']}")
        print("#" * 70)
        extra = []
        if args.bf16:
            extra.append("--bf16")
        if args.max_samples:
            extra.extend(["--max-samples", str(args.max_samples)])
        extra.extend(["--epochs", str(args.epochs)])
        cmd = [sys.executable, "src/models/train_severity.py"] + r["args"] + extra

        ret = subprocess.run(cmd)
        if ret.returncode != 0:
            print(f"❌ Failed: {r['desc']} (code {ret.returncode})")
        else:
            print(f"✅ Finished: {r['desc']}")

    # Final comparison
    print("\n" + "=" * 70)
    print("  Running Consolidated Comparison...")
    print("=" * 70)
    subprocess.run([sys.executable, "src/models/train_severity.py", "--evaluate-all"])

    # Select winners
    subprocess.run([sys.executable, "src/models/train_severity.py", "--select-winners"])


if __name__ == "__main__":
    main()
