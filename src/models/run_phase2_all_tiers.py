"""
run_phase2_all_tiers.py — Orchestrator: Train and evaluate Phase 2 models across all tiers.

Pipeline:
  1. Tier 1 (C/C++): CodeT5-v2, GraphCodeBERT-v2, CodeBERT-MOO (AIBugHunter), Fixed Ensemble
  2. Tier 2 (C++, Python, PHP): CodeT5-v2 and GraphCodeBERT-v2 warm-started from Tier 1 winner
  3. Tier 3 (Shared low-resource): CodeT5-v2 and GraphCodeBERT-v2 with <LANG=xx> tokens
  4. Auto-selects and links best model per tier into models/saved/phase2_winner_<tier>/

Usage:
    # Dry run — show run plan without training
    python src/models/run_phase2_all_tiers.py --dry-run

    # Run everything (CUDA Windows or full run)
    python src/models/run_phase2_all_tiers.py --bf16

    # Run only a specific tier
    python src/models/run_phase2_all_tiers.py --only-tier tier1_c_cpp --bf16
    python src/models/run_phase2_all_tiers.py --only-tier tier2_python --bf16
"""

import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

import sys
import json
import argparse
import subprocess
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
        print("Run Phase 0.5 audit first: python src/data/audit_multilang.py")
        sys.exit(1)
    with open(manifest_path, "r") as f:
        return json.load(f)


def build_phase2_run_plan(only_tier=None, only_model=None):
    runs = []

    # ── Tier 1: C/C++ ────────────────────────────────────────────────────────
    if only_tier is None or only_tier == "tier1_c_cpp":
        if only_model is None or only_model == "codet5":
            runs.append({
                "tier": "tier1_c_cpp",
                "model": "codet5",
                "script": "src/models/train_cwe.py",
                "desc": "Tier 1 CodeT5-v2 (C/C++)",
                "args": ["--model", "codet5", "--tier", "tier1_c_cpp", "--variant-tag", "v2"],
            })
        if only_model is None or only_model == "graphcodebert":
            runs.append({
                "tier": "tier1_c_cpp",
                "model": "graphcodebert",
                "script": "src/models/train_cwe.py",
                "desc": "Tier 1 GraphCodeBERT-v2 (C/C++)",
                "args": ["--model", "graphcodebert", "--tier", "tier1_c_cpp", "--variant-tag", "v2"],
            })
        if only_model is None or only_model == "codebert_moo":
            runs.append({
                "tier": "tier1_c_cpp",
                "model": "codebert_moo",
                "script": "src/models/train_codebert_moo.py",
                "desc": "Tier 1 CodeBERT-MOO-v2 (AIBugHunter Multi-Objective)",
                "args": ["--tier", "tier1_c_cpp"],
            })

    # ── Tier 2: Per-Language ────────────────────────────────────────────────
    tier2_map = [
        ("tier2_cpp", "C++"),
        ("tier2_python", "Python"),
        ("tier2_php", "PHP"),
    ]
    warm_start_ckpt = os.path.join(MODELS_DIR, "phase1_winner_tier1_c_cpp")

    for tier_key, lang_name in tier2_map:
        if only_tier is None or only_tier == tier_key:
            if only_model is None or only_model == "graphcodebert":
                runs.append({
                    "tier": tier_key,
                    "model": "graphcodebert",
                    "script": "src/models/train_cwe.py",
                    "desc": f"Tier 2 GraphCodeBERT-v2 ({lang_name}, warm-started)",
                    "args": [
                        "--model", "graphcodebert",
                        "--tier", tier_key,
                        "--warm-start", warm_start_ckpt,
                        "--variant-tag", "v2",
                    ],
                })
            if only_model is None or only_model == "codet5":
                runs.append({
                    "tier": tier_key,
                    "model": "codet5",
                    "script": "src/models/train_cwe.py",
                    "desc": f"Tier 2 CodeT5-v2 ({lang_name}, warm-started)",
                    "args": [
                        "--model", "codet5",
                        "--tier", tier_key,
                        "--warm-start", warm_start_ckpt,
                        "--variant-tag", "v2",
                    ],
                })

    # ── Tier 3: Shared Multilingual ─────────────────────────────────────────
    if only_tier is None or only_tier == "tier3_shared":
        if only_model is None or only_model == "codet5":
            runs.append({
                "tier": "tier3_shared",
                "model": "codet5",
                "script": "src/models/train_cwe.py",
                "desc": "Tier 3 Shared CodeT5-v2 (<LANG=xx> tokens)",
                "args": [
                    "--model", "codet5",
                    "--tier", "tier3_shared",
                    "--use-lang-tokens",
                    "--variant-tag", "v2",
                ],
            })
        if only_model is None or only_model == "graphcodebert":
            runs.append({
                "tier": "tier3_shared",
                "model": "graphcodebert",
                "script": "src/models/train_cwe.py",
                "desc": "Tier 3 Shared GraphCodeBERT-v2 (<LANG=xx> tokens)",
                "args": [
                    "--model", "graphcodebert",
                    "--tier", "tier3_shared",
                    "--use-lang-tokens",
                    "--variant-tag", "v2",
                ],
            })

    return runs


def main():
    parser = argparse.ArgumentParser(description="Run Phase 2 multi-tier CWE pipeline.")
    parser.add_argument("--only-tier", type=str, default=None,
                        choices=["tier1_c_cpp", "tier2_cpp", "tier2_python", "tier2_php", "tier3_shared"])
    parser.add_argument("--only-model", type=str, default=None,
                        choices=["codet5", "graphcodebert", "codebert_moo"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--bf16", action="store_true")
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--epochs", type=int, default=15)
    args = parser.parse_args()

    runs = build_phase2_run_plan(args.only_tier, args.only_model)

    print("=" * 70)
    print("  PHASE 2 MULTI-TIER EXECUTION PLAN")
    print(f"  Total Scheduled Runs: {len(runs)}")
    print("=" * 70)

    for i, r in enumerate(runs, 1):
        extra = []
        if args.bf16: extra.append("--bf16")
        if args.max_samples: extra.extend(["--max-samples", str(args.max_samples)])
        extra.extend(["--epochs", str(args.epochs)])
        cmd = [sys.executable, r["script"]] + r["args"] + extra
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
        if args.bf16: extra.append("--bf16")
        if args.max_samples: extra.extend(["--max-samples", str(args.max_samples)])
        extra.extend(["--epochs", str(args.epochs)])
        cmd = [sys.executable, r["script"]] + r["args"] + extra

        ret = subprocess.run(cmd)
        if ret.returncode != 0:
            print(f"❌ Failed: {r['desc']} (code {ret.returncode})")
        else:
            print(f"✅ Finished: {r['desc']}")

    # If Tier 1 was run, run the ensemble evaluation
    if args.only_tier is None or args.only_tier == "tier1_c_cpp":
        print("\n" + "=" * 70)
        print("  Evaluating Tier 1 Fixed Ensemble...")
        print("=" * 70)
        subprocess.run([sys.executable, "src/models/train_cwe.py", "--ensemble", "--variant-tag", "v2"])


if __name__ == "__main__":
    main()
