#!/usr/bin/env python3
"""
run_phase0_checks.py — Run all Phase 0 verification checks in sequence.

Usage:
    python run_phase0_checks.py
"""
import subprocess
import sys


def run_step(name: str, cmd: list[str]) -> bool:
    """Run a verification step."""
    print()
    print("━" * 60)
    print(f"  {name}")
    print("━" * 60)
    
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print(f"\n  ✅ {name} — PASSED")
    else:
        print(f"\n  ❌ {name} — FAILED (exit code {result.returncode})")
    
    return result.returncode == 0


def main():
    print()
    print("╔" + "═" * 58 + "╗")
    print("║           Phase 0 — Verification Checks                 ║")
    print("╚" + "═" * 58 + "╝")
    
    results = {}
    
    # Check 1: Dataset download and exploration
    results["Data Loading"] = run_step(
        "Data Loading & Exploration",
        [sys.executable, "-m", "src.data.load_data"]
    )
    
    # Check 2: HuggingFace model
    results["HuggingFace Model"] = run_step(
        "HuggingFace Model (CodeBERT)",
        [sys.executable, "-m", "src.utils.verify_hf_model"]
    )
    
    # Check 3: Ollama
    results["Ollama"] = run_step(
        "Ollama Installation & Inference",
        [sys.executable, "-m", "src.utils.verify_ollama"]
    )
    
    # Summary
    print()
    print("╔" + "═" * 58 + "╗")
    print("║           Phase 0 — Results Summary                     ║")
    print("╚" + "═" * 58 + "╝")
    print()
    
    for name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {name:<30} {status}")
    
    all_passed = all(results.values())
    print()
    if all_passed:
        print("🎉 All Phase 0 checks passed! Ready for Phase 1.")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"⚠️  {len(failed)} check(s) failed: {', '.join(failed)}")
        print("   Fix the issues above and re-run this script.")
    print()


if __name__ == "__main__":
    main()
