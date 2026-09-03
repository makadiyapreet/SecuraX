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
    # BigVul uses 'vul' column (1 = vulnerable, 0 = not vulnerable)
    vul_col = None
    for candidate in ["vul", "vulnerable", "target", "label", "VF"]:
        if candidate in df.columns:
            vul_col = candidate
            break
    
    if vul_col is None:
        print("⚠️  Could not auto-detect vulnerability flag column.")
        print(f"   Available columns: {list(df.columns)}")
        return None
    
    print("=" * 60)
    print(f"VULNERABILITY FLAG (column: '{vul_col}')")
    print("=" * 60)
    
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
        # Check if CWE info is embedded in another column
        print("⚠️  No explicit CWE column found.")
        print(f"   Available columns: {list(df.columns)}")
        return None
    
    print("=" * 60)
    print(f"CWE-ID DISTRIBUTION (column: '{cwe_col}')")
    print("=" * 60)
    
    cwe_counts = df[cwe_col].value_counts()
    unique_cwes = len(cwe_counts)
    print(f"  Unique CWE-ids: {unique_cwes}")
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
        print()
        print("  DECISION: Since BigVul does not always include a CVSS column,")
        print("  we will map CWE-ids to CVSS base scores using the NVD/CWE")
        print("  severity mappings, or use a lookup table.")
        print("  This will be implemented in Phase 1.")
        print()
        return None
    
    print(f"  Column: '{sev_col}'")
    print(f"  Dtype:  {df[sev_col].dtype}")
    print()
    
    # Check if continuous or categorical
    unique_vals = df[sev_col].dropna().unique()
    
    if df[sev_col].dtype in [np.float64, np.float32, np.int64, np.int32]:
        print(f"  Format: CONTINUOUS (numeric)")
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
            print(f"    {label:<10} [{lo:.1f}–{hi:.1f}]: {count:>8,} samples")
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
        print("  The dataset is extracted from C/C++ projects.")
        print()
        
        # Check if file extension info is available
        for col in df.columns:
            if "file" in col.lower() or "path" in col.lower() or "name" in col.lower():
                print(f"  Potential file path column: '{col}'")
                sample = df[col].dropna().head(5).tolist()
                print(f"  Sample values: {sample}")
                print()
        
        print("  DECISION: Languages will be inferred from file extensions")
        print("  or hardcoded as C/C++ for BigVul.")
        return None
    
    print(f"  Column: '{lang_col}'")
    lang_counts = df[lang_col].value_counts()
    for lang, count in lang_counts.items():
        pct = count / len(df) * 100
        print(f"    {lang:<15} {count:>8,}  ({pct:.1f}%)")
    print()
    return lang_col


def explore_code_snippets(df: pd.DataFrame) -> None:
    """Analyze code snippet columns."""
    code_cols = []
    for candidate in ["func_before", "func_after", "code", "source", "snippet",
                       "processed_func", "vul_func_with_fix"]:
        if candidate in df.columns:
            code_cols.append(candidate)
    
    print("=" * 60)
    print("CODE SNIPPET COLUMNS")
    print("=" * 60)
    
    if not code_cols:
        print("  ⚠️  No recognized code snippet columns found.")
        print(f"   All columns: {list(df.columns)}")
    else:
        for col in code_cols:
            non_null = df[col].notna().sum()
            avg_len = df[col].dropna().str.len().mean()
            print(f"  '{col}': {non_null:,} non-null, avg length {avg_len:.0f} chars")
        
        # Show a sample
        main_col = code_cols[0]
        print(f"\n  Sample from '{main_col}' (first 200 chars):")
        sample = df[main_col].dropna().iloc[0][:200]
        print(f"  ---")
        for line in sample.split("\n")[:8]:
            print(f"  | {line}")
        print(f"  ---")
    print()


def create_splits(df: pd.DataFrame, vul_col: str, cwe_col: str) -> dict:
    """
    Create stratified train/val/test splits.
    
    Stratification strategy:
    - Primary: stratify by vulnerability flag (vul_col)
    - Secondary: within vulnerable samples, stratify by CWE-id
    
    This ensures each split has proportional representation of:
    1. Vulnerable vs. non-vulnerable samples
    2. Different CWE types
    """
    from sklearn.model_selection import train_test_split
    
    print("=" * 60)
    print("TRAIN / VALIDATION / TEST SPLIT")
    print("=" * 60)
    print(f"  Strategy: Stratified split")
    print(f"  Ratios:   {SPLIT_RATIOS}")
    print(f"  Seed:     {RANDOM_SEED}")
    print()
    
    # Create a composite stratification key
    # For non-vulnerable samples, use "non-vul" as the key
    # For vulnerable samples, use the CWE-id
    if vul_col and cwe_col:
        strat_key = df.apply(
            lambda row: f"vul_{row[cwe_col]}" if row[vul_col] == 1 else "non_vul",
            axis=1
        )
        # For CWE classes with very few samples, group them as "vul_rare"
        key_counts = strat_key.value_counts()
        rare_keys = key_counts[key_counts < 5].index
        strat_key = strat_key.replace({k: "vul_rare" for k in rare_keys})
        strat_label = "vulnerability flag + CWE-id"
    elif vul_col:
        strat_key = df[vul_col].astype(str)
        strat_label = "vulnerability flag"
    else:
        strat_key = None
        strat_label = "random (no stratification column found)"
    
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
    
    # Show class balance in each split
    if vul_col:
        print()
        print(f"  Vulnerable samples per split:")
        print(f"  {'Split':<10} {'Vul':>8} {'Non-Vul':>10} {'Vul %':>8}")
        print(f"  {'-'*38}")
        for name, idx in splits.items():
            subset = df.loc[idx]
            vul = (subset[vul_col] == 1).sum()
            non_vul = (subset[vul_col] == 0).sum()
            pct = vul / len(subset) * 100
            print(f"  {name:<10} {vul:>8,} {non_vul:>10,} {pct:>7.1f}%")
    
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
    
    # 7. Code snippets
    explore_code_snippets(df)
    
    # 8. Stratified splits
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
    print(f"  Vulnerability column: {vul_col or 'NOT FOUND'}")
    print(f"  CWE-id column:        {cwe_col or 'NOT FOUND'}")
    print(f"  Severity column:      {sev_col or 'NOT FOUND'}")
    print(f"  Language column:       {lang_col or 'NOT FOUND (C/C++ assumed)'}")
    print(f"  Split strategy:       Stratified 80/10/10 (seed={RANDOM_SEED})")
    print()
    print("✅ Phase 0 data exploration complete.")
    print()


if __name__ == "__main__":
    main()
