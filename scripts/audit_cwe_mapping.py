#!/usr/bin/env python3
"""
scripts/audit_cwe_mapping.py — Scan CWE Taxonomy for duplicate CWE group assignments.

Produces:
  - results/audit/cwe_duplicates.csv
"""

import sys
from pathlib import Path
import pandas as pd
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.cwe_taxonomy import CWE_SEMANTIC_GROUPS

AUDIT_DIR = PROJECT_ROOT / "results" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 70)
    print("  SecuraX Audit: CWE Taxonomy 1-to-1 Mapping Verification")
    print("=" * 70)

    cwe_to_groups = defaultdict(list)
    for group, cwes in CWE_SEMANTIC_GROUPS.items():
        for cwe in cwes:
            cwe_to_groups[cwe].append(group)

    duplicates = []
    for cwe, groups in cwe_to_groups.items():
        if len(groups) > 1:
            duplicates.append({
                "cwe_id": cwe,
                "group_count": len(groups),
                "groups": "; ".join(groups),
                "is_ambiguous": True,
            })

    dup_df = pd.DataFrame(duplicates)
    csv_p = AUDIT_DIR / "cwe_duplicates.csv"
    dup_df.to_csv(csv_p, index=False)
    print(f"[OUTPUT] Found {len(duplicates)} duplicate CWE mappings across groups.")
    print(f"[OUTPUT] Saved duplicate report to {csv_p}")
    if len(duplicates) == 0:
        print("✅ SUCCESS: Every CWE maps strictly 1-to-1 to exactly one semantic group!")
    else:
        print(dup_df)


if __name__ == "__main__":
    main()

