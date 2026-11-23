#!/usr/bin/env python3
"""
scripts/build_heldout.py — SecuraX Master Audit: Extract Held-Out Real Data (CVEFixes) Test Sets.

Builds genuine held-out evaluation sets of before/after commit pairs across languages:
- Vulnerable before-patch function (label = 1)
- Remediated after-patch function (label = 0)

Outputs:
  - data/heldout/{lang}.jsonl
  - data/heldout/MANIFEST.md
"""

import json
import hashlib
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
HELDOUT_DIR = PROJECT_ROOT / "data" / "heldout"
HELDOUT_DIR.mkdir(parents=True, exist_ok=True)


def code_hash(s: str) -> str:
    return hashlib.sha256(s.strip().encode("utf-8")).hexdigest()


def build_heldout():
    print("=" * 70)
    print("  SecuraX Audit: Building Real-World Held-Out Test Sets (CVEFixes)")
    print("=" * 70)

    # Load existing train hashes to guarantee zero leakage
    train_hashes = set()
    for t in ["tier1_c_cpp", "tier2_cpp", "tier2_php", "tier2_python", "tier3_shared"]:
        tp = PROCESSED_DIR / t / "vf" / "train.csv"
        if tp.exists():
            df = pd.read_csv(tp)
            for c in df["func_before"].dropna():
                train_hashes.add(code_hash(c))

    print(f"[PREP] Loaded {len(train_hashes):,} training code hashes for exclusion.")

    lang_sources = [
        ("php", PROCESSED_DIR / "tier2_php" / "vf" / "test.csv", None),
        ("python", PROCESSED_DIR / "tier2_python" / "vf" / "test.csv", None),
        ("cpp", PROCESSED_DIR / "tier2_cpp" / "vf" / "test.csv", None),
        ("javascript", PROCESSED_DIR / "tier3_shared" / "vf" / "test.csv", "JavaScript"),
        ("java", PROCESSED_DIR / "tier3_shared" / "vf" / "test.csv", "Java"),
    ]

    manifest_records = []

    for lang_name, src_file, lang_filter in lang_sources:
        if not src_file.exists():
            print(f"Warning: {src_file} does not exist.")
            continue

        df = pd.read_csv(src_file)
        if lang_filter:
            df = df[df["language"].str.lower() == lang_filter.lower()]

        # Filter rows with both func_before and func_after
        valid_pairs = []
        for _, row in df.iterrows():
            f_before = str(row.get("func_before", "")).strip()
            f_after = str(row.get("func_after", "")).strip()
            if len(f_before) > 30 and len(f_after) > 30 and f_before != f_after:
                h_b = code_hash(f_before)
                h_a = code_hash(f_after)
                # Check exclusion against train set
                if h_b not in train_hashes and h_a not in train_hashes:
                    pair_id = f"PAIR_{lang_name.upper()}_{len(valid_pairs)+1:03d}"
                    valid_pairs.append({
                        "pair_id": pair_id,
                        "language": lang_name,
                        "cve_id": str(row.get("cve_id", "N/A")),
                        "cwe_id": str(row.get("cwe_id", "N/A")),
                        "func_before": f_before,
                        "func_after": f_after,
                    })
            if len(valid_pairs) >= 50:
                break

        out_file = HELDOUT_DIR / f"{lang_name}.jsonl"
        with open(out_file, "w", encoding="utf-8") as f:
            for p in valid_pairs:
                # Write before (vul=1)
                f.write(json.dumps({
                    "id": f"{p['pair_id']}_VULN",
                    "pair_id": p["pair_id"],
                    "language": p["language"],
                    "cve_id": p["cve_id"],
                    "cwe_id": p["cwe_id"],
                    "label": 1,
                    "type": "before_patch",
                    "code": p["func_before"],
                }) + "\n")
                # Write after (vul=0)
                f.write(json.dumps({
                    "id": f"{p['pair_id']}_SAFE",
                    "pair_id": p["pair_id"],
                    "language": p["language"],
                    "cve_id": p["cve_id"],
                    "cwe_id": p["cwe_id"],
                    "label": 0,
                    "type": "after_patch",
                    "code": p["func_after"],
                }) + "\n")

        total_samples = len(valid_pairs) * 2
        print(f"[SAVED] {out_file.name}: {len(valid_pairs)} pairs ({total_samples} samples: {len(valid_pairs)} vuln, {len(valid_pairs)} patched)")
        manifest_records.append({
            "language": lang_name,
            "pairs": len(valid_pairs),
            "total_samples": total_samples,
            "file": out_file.name,
        })

    # Write MANIFEST.md
    manifest_p = HELDOUT_DIR / "MANIFEST.md"
    with open(manifest_p, "w", encoding="utf-8") as f:
        f.write("# SecuraX Held-Out Real Data Test Bed (CVEFixes)\n\n")
        f.write("**Generated:** 2026-11-07  \n")
        f.write("**Source:** Genuine in-the-wild vulnerability fixes from CVEFixes git commits.\n\n")
        f.write("Each language test bed consists of strict before/after commit pairs:\n")
        f.write("- **Before-Patch Function (`label = 1`):** Vulnerable implementation as reported in CVE.\n")
        f.write("- **After-Patch Function (`label = 0`):** Secure remediation committed by project maintainers.\n\n")
        f.write("| Language | Pairs | Total Samples | Vuln Samples | Patched Samples | Dataset File |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :--- |\n")
        for m in manifest_records:
            f.write(f"| `{m['language']}` | {m['pairs']} | {m['total_samples']} | {m['pairs']} | {m['pairs']} | `{m['file']}` |\n")

    print(f"[OUTPUT] Generated {manifest_p}")


if __name__ == "__main__":
    build_heldout()

