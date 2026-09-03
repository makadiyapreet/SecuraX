#!/usr/bin/env python3
"""
load_data.py — Load, explore, and validate the BigVul dataset.

Prints:
  - Total sample count
  - Vulnerable vs. non-vulnerable balance
  - Class balance across CWE-ids (top-N and full distribution)
  - Severity score format analysis (continuous CVSS vs categorical)
  - Programming languages present
  - Column schema and data types

Also performs the stratified train/val/test split and saves split indices.

Usage:
    python -m src.data.load_data
"""
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import numpy as np
from collections import Counter

from src.config import (
    BIGVUL_PATH, PROCESSED_DATA_DIR,
    SPLIT_RATIOS, RANDOM_SEED, SEVERITY_BINS
)


def load_bigvul(path: Path = BIGVUL_PATH) -> pd.DataFrame:
    """Load the BigVul CSV dataset."""
    if not path.exists():
        print(f"❌ Dataset not found at: {path}")
        print(f"   Run:  python -m src.data.download_bigvul")
        sys.exit(1)
    
    print(f"Loading dataset from: {path}")
    df = pd.read_csv(path, low_memory=False)
    print(f"✅ Loaded {len(df):,} rows, {len(df.columns)} columns\n")
    return df


def explore_schema(df: pd.DataFrame) -> None:
    """Print column names, dtypes, and non-null counts."""
    print("=" * 60)
    print("DATASET SCHEMA")
    print("=" * 60)
    print(f"Shape: {df.shape[0]:,} rows × {df.shape[1]} columns\n")
    
    print(f"{'Column':<30} {'Dtype':<15} {'Non-Null':>10} {'Null':>8}")
    print("-" * 65)
    for col in df.columns:
        non_null = df[col].notna().sum()
        null_count = df[col].isna().sum()
        print(f"{col:<30} {str(df[col].dtype):<15} {non_null:>10,} {null_count:>8,}")
    print()


def explore_vulnerability_flag(df: pd.DataFrame) -> str:
    """Identify and print the vulnerability flag column."""
    # Check for explicit vulnerability flag column
    vul_col = None
    for candidate in ["vul", "vulnerable", "target", "label", "VF"]:
        if candidate in df.columns:
            vul_col = candidate
            break
    
    print("=" * 60)
    print("VULNERABILITY FLAG ANALYSIS")
    print("=" * 60)
    
    if vul_col is None:
        # This dataset version is metadata-only: all rows are CVE records
        # (all vulnerable). There is no explicit vul/non-vul flag.
        has_cve = "cve_id" in df.columns
        cve_non_null = df["cve_id"].notna().sum() if has_cve else 0
        
        print("  ⚠️  No explicit vulnerability flag column found.")
        print()
        print("  ANALYSIS: This dataset version (all_c_cpp_release2.0.csv) is a")
        print("  CVE metadata dataset. Every row represents a known vulnerability.")
        if has_cve:
            print(f"  Evidence: {cve_non_null:,} of {len(df):,} rows have a CVE-id.")
        print()
        print("  IMPLICATION: All {len(df):,} samples are VULNERABLE.")
        print("  For binary vulnerability detection (Phase 1), we will need")
        print("  to add non-vulnerable code samples. Options:")
        print("    1. Use Devign dataset (has balanced vul/non-vul C/C++ functions)")
        print("    2. Sample non-vulnerable functions from the same projects")
        print("    3. Combine with CVEfixes dataset which includes both")
        print()
        print("  DECISION REQUIRED: How to source non-vulnerable samples.")
        print()
        return None
    
    print(f"  Column: '{vul_col}'")
    counts = df[vul_col].value_counts()
    total = len(df)
    for val, count in counts.items():
        pct = count / total * 100
        label = "Vulnerable" if val == 1 else "Non-vulnerable"
        print(f"  {label} ({val}): {count:>8,}  ({pct:.1f}%)")
    
    ratio = counts.get(1, 0) / counts.get(0, 1)
    print(f"\n  Imbalance ratio (vul/non-vul): 1:{1/ratio:.1f}")
    print()
    return vul_col


def explore_cwe_distribution(df: pd.DataFrame) -> str:
    """Print CWE-id distribution."""
    cwe_col = None
    for candidate in ["cwe_id", "CWE ID", "cwe", "CWE-id", "CWE"]:
        if candidate in df.columns:
            cwe_col = candidate
            break
    
    if cwe_col is None:
        print("⚠️  No explicit CWE column found.")
        print(f"   Available columns: {list(df.columns)}")
        return None
    
    print("=" * 60)
    print(f"CWE-ID DISTRIBUTION (column: '{cwe_col}')")
    print("=" * 60)
    
    cwe_counts = df[cwe_col].value_counts()
    unique_cwes = len(cwe_counts)
    null_cwes = df[cwe_col].isna().sum()
    print(f"  Unique CWE-ids: {unique_cwes}")
    print(f"  Rows with CWE:  {df[cwe_col].notna().sum():,}")
    print(f"  Rows without:   {null_cwes:,}")
    print()
    
    # Top 20 CWEs
    print(f"  Top 20 CWE-ids:")
    print(f"  {'CWE-ID':<20} {'Count':>8} {'%':>8}")
    print(f"  {'-'*38}")
    for cwe, count in cwe_counts.head(20).items():
        pct = count / len(df) * 100
        print(f"  {str(cwe):<20} {count:>8,} {pct:>7.1f}%")
    
    if unique_cwes > 20:
        remaining = cwe_counts.iloc[20:].sum()
        print(f"  {'(other '+str(unique_cwes-20)+' CWEs)':<20} {remaining:>8,} {remaining/len(df)*100:>7.1f}%")
    
    # CWE class size analysis (for stratification planning)
    print()
    print(f"  CWE class size distribution:")
    bins = [0, 1, 5, 10, 50, 100, 500, float('inf')]
    labels = ['1', '2-5', '6-10', '11-50', '51-100', '101-500', '500+']
    class_sizes = pd.cut(cwe_counts.values, bins=bins, labels=labels)
    size_dist = pd.Series(class_sizes).value_counts().sort_index()
    for bucket, count in size_dist.items():
        print(f"    {str(bucket)+' samples':<20} {count:>4} CWE classes")
    
    print()
    return cwe_col


def explore_severity(df: pd.DataFrame) -> str:
    """Analyze severity score format."""
    sev_col = None
    for candidate in ["cvss", "score", "severity", "cvss_score", "CVSS", "Severity"]:
        if candidate in df.columns:
            sev_col = candidate
            break
    
    # Also check if there's a CVSS-like score in any column
    if sev_col is None:
        for col in df.columns:
            if "score" in col.lower() or "cvss" in col.lower() or "severity" in col.lower():
                sev_col = col
                break
    
    print("=" * 60)
    print("SEVERITY SCORE ANALYSIS")
    print("=" * 60)
    
    if sev_col is None:
        print("  ⚠️  No explicit severity/CVSS column found.")
        print(f"   Available columns: {list(df.columns)}")
        return None
    
    print(f"  Column: '{sev_col}'")
    print(f"  Dtype:  {df[sev_col].dtype}")
    print()
    
    # Check if continuous or categorical
    unique_vals = df[sev_col].dropna().unique()
    
    if df[sev_col].dtype in [np.float64, np.float32, np.int64, np.int32]:
        print(f"  Format: CONTINUOUS (CVSS v2 base score)")
        print(f"  Range:  {df[sev_col].min():.2f} – {df[sev_col].max():.2f}")
        print(f"  Mean:   {df[sev_col].mean():.2f}")
        print(f"  Median: {df[sev_col].median():.2f}")
        print(f"  Std:    {df[sev_col].std():.2f}")
        print(f"  Null:   {df[sev_col].isna().sum():,}")
        print()
        
        # Show proposed binning
        print("  PROPOSED SEVERITY BINS (CVSS v2 standard):")
        for label, (lo, hi) in SEVERITY_BINS.items():
            mask = (df[sev_col] >= lo) & (df[sev_col] <= hi)
            count = mask.sum()
            pct = count / df[sev_col].notna().sum() * 100
            print(f"    {label:<10} [{lo:.1f}–{hi:.1f}]: {count:>8,} samples ({pct:.1f}%)")
        
        nulls = df[sev_col].isna().sum()
        if nulls > 0:
            print(f"    {'(null)':<10}             {nulls:>8,} samples")
    else:
        print(f"  Format: CATEGORICAL")
        print(f"  Unique values ({len(unique_vals)}):")
        for val in sorted(unique_vals)[:20]:
            count = (df[sev_col] == val).sum()
            print(f"    {val}: {count:,}")
    
    print()
    return sev_col


def explore_languages(df: pd.DataFrame) -> str:
    """Identify programming languages in the dataset."""
    lang_col = None
    for candidate in ["lang", "language", "PL", "programming_language", "project_language"]:
        if candidate in df.columns:
            lang_col = candidate
            break
    
    print("=" * 60)
    print("PROGRAMMING LANGUAGES")
    print("=" * 60)
    
    if lang_col is None:
        print("  ⚠️  No explicit language column found.")
        print("  BigVul primarily contains C/C++ code.")
        return None
    
    print(f"  Column: '{lang_col}'")
    lang_counts = df[lang_col].value_counts()
    for lang, count in lang_counts.items():
        pct = count / len(df) * 100
        print(f"    {lang:<15} {count:>8,}  ({pct:.1f}%)")
    print()
    return lang_col


def explore_code_columns(df: pd.DataFrame) -> list:
    """Analyze code snippet / commit columns."""
    # Check for actual code columns
    code_candidates = [
        "func_before", "func_after", "code", "source", "snippet",
        "processed_func", "vul_func_with_fix",
    ]
    code_cols = [c for c in code_candidates if c in df.columns]
    
    # Check for commit/version reference columns
    ref_candidates = [
        "version_before_fix", "version_after_fix", "commit_id",
        "ref_link", "cve_page",
    ]
    ref_cols = [c for c in ref_candidates if c in df.columns]
    
    print("=" * 60)
    print("CODE & REFERENCE COLUMNS")
    print("=" * 60)
    
    if code_cols:
        print("  ✅ Code snippet columns found:")
        for col in code_cols:
            non_null = df[col].notna().sum()
            avg_len = df[col].dropna().str.len().mean()
            print(f"    '{col}': {non_null:,} non-null, avg {avg_len:.0f} chars")
        
        main_col = code_cols[0]
        print(f"\n  Sample from '{main_col}' (first 200 chars):")
        sample = df[main_col].dropna().iloc[0][:200]
        print(f"  ---")
        for line in sample.split("\n")[:8]:
            print(f"  | {line}")
        print(f"  ---")
    else:
        print("  ⚠️  No inline code snippet columns found.")
        print()
        print("  This dataset version contains CVE metadata + commit references,")
        print("  NOT inline source code. The actual code must be fetched from")
        print("  git repositories using the commit hashes.")
    
    if ref_cols:
        print()
        print("  Reference columns available:")
        for col in ref_cols:
            non_null = df[col].notna().sum()
            sample = str(df[col].dropna().iloc[0])[:60] if non_null > 0 else "N/A"
            print(f"    '{col}': {non_null:,} non-null")
            print(f"      Example: {sample}")
    
    print()
    
    if not code_cols:
        print("  ⚠️  CRITICAL: No code in this dataset version.")
        print()
        print("  For ML training, we need actual source code. Options:")
        print("    1. Use BigVul with code (available on HuggingFace as")
        print("       'benjis/bigvul' or similar processed versions)")
        print("    2. Use Devign dataset (balanced, includes C/C++ functions)")
        print("    3. Fetch code from git repos using commit_id + project columns")
        print("    4. Use this metadata for CWE/severity mapping and pair")
        print("       with a code-inclusive dataset")
        print()
    
    return code_cols


def explore_additional_metadata(df: pd.DataFrame) -> None:
    """Analyze additional useful columns."""
    print("=" * 60)
    print("ADDITIONAL METADATA")
    print("=" * 60)
    
    # vulnerability_classification (could be useful as secondary label)
    if "vulnerability_classification" in df.columns:
        vc = df["vulnerability_classification"].value_counts()
        non_null = df["vulnerability_classification"].notna().sum()
        print(f"  vulnerability_classification: {non_null:,} non-null, {len(vc)} unique")
        print(f"  Top 10:")
        for val, count in vc.head(10).items():
            print(f"    {str(val)[:40]:<42} {count:>6,}")
        print()
    
    # access_complexity, authentication_required (CVSS sub-scores)
    cvss_sub = ["access_complexity", "authentication_required",
                "confidentiality_impact", "integrity_impact", "availability_impact"]
    found_sub = [c for c in cvss_sub if c in df.columns]
    if found_sub:
        print(f"  CVSS v2 sub-scores available:")
        for col in found_sub:
            vals = df[col].value_counts()
            non_null = df[col].notna().sum()
            top = ", ".join(f"{v}({c})" for v, c in vals.head(3).items())
            print(f"    {col}: {non_null:,} non-null — {top}")
        print()
    
    # project distribution
    if "project" in df.columns:
        proj_counts = df["project"].value_counts()
        print(f"  Projects: {len(proj_counts)} unique")
        print(f"  Top 10:")
        for proj, count in proj_counts.head(10).items():
            print(f"    {str(proj)[:30]:<32} {count:>6,}")
        print()


def create_splits(df: pd.DataFrame, vul_col: str, cwe_col: str) -> dict:
    """
    Create stratified train/val/test splits.
    
    Since this dataset version has all vulnerable samples,
    stratification is by CWE-id to ensure proportional
    representation of each vulnerability type in each split.
    """
    from sklearn.model_selection import train_test_split
    
    print("=" * 60)
    print("TRAIN / VALIDATION / TEST SPLIT")
    print("=" * 60)
    print(f"  Strategy: Stratified split")
    print(f"  Ratios:   {SPLIT_RATIOS}")
    print(f"  Seed:     {RANDOM_SEED}")
    print()
    
    # Determine stratification key
    if cwe_col and df[cwe_col].notna().sum() > 0:
        # Stratify by CWE-id
        # Fill NaN CWEs with a placeholder for stratification
        strat_key = df[cwe_col].fillna("UNKNOWN").astype(str)
        
        # Group rare CWE classes (< 10 samples) to prevent split failures.
        # With an 80/10/10 split, a CWE needs ~10 samples minimum to have
        # at least 1 member in each split after two-stage stratification.
        key_counts = strat_key.value_counts()
        rare_keys = key_counts[key_counts < 10].index
        strat_key = strat_key.replace({k: "RARE_CWE" for k in rare_keys})
        n_grouped = len(rare_keys)
        strat_label = f"CWE-id ({len(key_counts)} original classes, {n_grouped} grouped as RARE_CWE)"
    elif vul_col:
        strat_key = df[vul_col].astype(str)
        strat_label = "vulnerability flag"
    else:
        strat_key = None
        strat_label = "random (no stratification column available)"
    
    # First split: train vs (val + test)
    val_test_ratio = SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]
    
    train_idx, val_test_idx = train_test_split(
        df.index,
        test_size=val_test_ratio,
        random_state=RANDOM_SEED,
        stratify=strat_key
    )
    
    # Second split: val vs test (50/50 of the remaining)
    val_ratio_of_remaining = SPLIT_RATIOS["val"] / val_test_ratio
    
    if strat_key is not None:
        strat_remaining = strat_key.loc[val_test_idx]
    else:
        strat_remaining = None
    
    val_idx, test_idx = train_test_split(
        val_test_idx,
        test_size=(1 - val_ratio_of_remaining),
        random_state=RANDOM_SEED,
        stratify=strat_remaining
    )
    
    splits = {"train": train_idx, "val": val_idx, "test": test_idx}
    
    print(f"  Stratification: {strat_label}")
    print()
    print(f"  {'Split':<10} {'Samples':>10} {'%':>8}")
    print(f"  {'-'*30}")
    for name, idx in splits.items():
        pct = len(idx) / len(df) * 100
        print(f"  {name:<10} {len(idx):>10,} {pct:>7.1f}%")
    print(f"  {'TOTAL':<10} {len(df):>10,} {'100.0':>7s}%")
    
    # Show CWE balance per split
    if cwe_col:
        print()
        print(f"  Top-5 CWE distribution per split:")
        top5 = df[cwe_col].value_counts().head(5).index.tolist()
        header = f"  {'Split':<8}" + "".join(f" {c:>10}" for c in top5)
        print(header)
        print(f"  {'-'*(8 + 11*len(top5))}")
        for name, idx in splits.items():
            subset = df.loc[idx]
            counts = "".join(f" {(subset[cwe_col]==c).sum():>10,}" for c in top5)
            print(f"  {name:<8}{counts}")
    
    print()
    
    # Save split indices
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    split_path = PROCESSED_DATA_DIR / "split_indices.npz"
    np.savez(
        split_path,
        train=np.array(train_idx),
        val=np.array(val_idx),
        test=np.array(test_idx),
    )
    print(f"  ✅ Split indices saved to: {split_path}")
    print()
    
    return splits


def main():
    print()
    print("╔" + "═" * 58 + "╗")
    print("║  BigVul Dataset — Exploration & Validation (Phase 0)    ║")
    print("╚" + "═" * 58 + "╝")
    print()
    
    # 1. Load
    df = load_bigvul()
    
    # 2. Schema
    explore_schema(df)
    
    # 3. Vulnerability flag
    vul_col = explore_vulnerability_flag(df)
    
    # 4. CWE distribution
    cwe_col = explore_cwe_distribution(df)
    
    # 5. Severity scores
    sev_col = explore_severity(df)
    
    # 6. Languages
    lang_col = explore_languages(df)
    
    # 7. Code columns
    code_cols = explore_code_columns(df)
    
    # 8. Additional metadata
    explore_additional_metadata(df)
    
    # 9. Stratified splits
    try:
        splits = create_splits(df, vul_col, cwe_col)
    except Exception as e:
        print(f"  ⚠️  Split creation failed: {e}")
        print(f"  This will be resolved once the dataset columns are confirmed.")
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total samples:        {len(df):,}")
    print(f"  All vulnerable:       {'YES' if vul_col is None else 'NO'}")
    print(f"  CWE-id column:        {cwe_col or 'NOT FOUND'}")
    print(f"    Unique CWE-ids:     {df[cwe_col].nunique() if cwe_col else 'N/A'}")
    print(f"  Severity column:      {sev_col or 'NOT FOUND'}")
    print(f"  Language column:       {lang_col or 'NOT FOUND (C/C++ assumed)'}")
    print(f"  Inline code:          {'YES' if code_cols else 'NO — metadata only'}")
    print(f"  Split strategy:       Stratified by CWE-id, 80/10/10 (seed={RANDOM_SEED})")
    print()
    
    if not code_cols:
        print("⚠️  IMPORTANT: This dataset version is metadata-only.")
        print("   The actual source code must be obtained separately.")
        print("   See 'CODE & REFERENCE COLUMNS' section above for options.")
        print()
    
    print("✅ Phase 0 data exploration complete.")
    print()


if __name__ == "__main__":
    main()
