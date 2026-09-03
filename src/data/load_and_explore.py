"""
load_and_explore.py — Load and explore the BigVul dataset.

Prints:
  - Total sample count
  - Class balance across CWE-ids (top-N + tail)
  - Vulnerability flag distribution (VF: 0 vs 1)
  - Severity score format analysis (continuous CVSS vs categorical)
  - Programming languages present
  - Train/Val/Test split preview (stratified by CWE-id)

Usage:
    python src/data/load_and_explore.py [--data-path data/raw/bigvul_all_c_cpp.csv]
    python src/data/load_and_explore.py --use-huggingface
"""

import os
import sys
import argparse
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)

# ─── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DEFAULT_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "bigvul_all_c_cpp.csv")

# CVSS severity buckets (NVD standard)
CVSS_BUCKETS = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

# Train / Val / Test split ratios
SPLIT_RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}

# Minimum samples per CWE class to be included in stratified split
# With 70/15/15 ratios, need ≥7 samples for at least 1 per split
MIN_SAMPLES_PER_CLASS = 7


# ─── Data Loading ────────────────────────────────────────────────────────────


def load_from_csv(csv_path: str) -> pd.DataFrame:
    """Load BigVul dataset from local CSV file."""
    print(f"Loading dataset from: {csv_path}")
    if not os.path.exists(csv_path):
        print(f"❌ File not found: {csv_path}")
        print("   Run: python src/data/download_bigvul.py")
        sys.exit(1)

    df = pd.read_csv(csv_path, low_memory=False)
    print(f"✅ Loaded {len(df):,} rows, {len(df.columns)} columns")
    return df


def load_from_huggingface() -> pd.DataFrame:
    """Load BigVul from HuggingFace datasets hub (function-level, recommended)."""
    try:
        from datasets import load_dataset

        print("Loading BigVul from HuggingFace Hub (benjis/bigvul)...")
        print("This is the function-level dataset with ~217K samples.")
        ds = load_dataset("benjis/bigvul")

        # Load all splits and combine
        dfs = []
        for split_name in ["train", "validation", "test"]:
            if split_name in ds:
                split_df = ds[split_name].to_pandas()
                split_df["_split"] = split_name
                dfs.append(split_df)
                print(f"  {split_name:>12}: {len(split_df):>8,} samples")

        df = pd.concat(dfs, ignore_index=True)
        print(f"  {'Total':>12}: {len(df):>8,} samples")
        print(f"✅ Loaded {len(df):,} rows from HuggingFace")
        return df
    except Exception as e:
        print(f"❌ HuggingFace loading failed: {e}")
        print("   Falling back to local CSV...")
        return load_from_csv(DEFAULT_CSV_PATH)


# ─── Exploration Functions ───────────────────────────────────────────────────


def explore_basic_stats(df: pd.DataFrame) -> None:
    """Print basic dataset statistics."""
    print("\n" + "=" * 70)
    print("1. BASIC DATASET STATISTICS")
    print("=" * 70)

    print(f"\n  Total samples:     {len(df):>10,}")
    print(f"  Total columns:     {len(df.columns):>10}")
    print(f"  Memory usage:      {df.memory_usage(deep=True).sum() / (1024**2):>10.1f} MB")

    print(f"\n  Columns: {list(df.columns)}")


def explore_vulnerability_labels(df: pd.DataFrame) -> str:
    """Analyze vulnerability flag distribution. Returns the VF column name."""
    print("\n" + "=" * 70)
    print("2. VULNERABILITY FLAG (VF) DISTRIBUTION")
    print("=" * 70)

    # BigVul uses 'vul' column (0 = non-vulnerable, 1 = vulnerable)
    vf_col = None
    for candidate in ["vul", "vulnerable", "target", "label", "Vulnerability"]:
        if candidate in df.columns:
            vf_col = candidate
            break

    if vf_col is None:
        # BigVul GitHub CSV is CVE-level: ALL rows are confirmed vulnerabilities
        # Check if this is the case by looking for CVE-specific columns
        if "cve_id" in df.columns:
            print("\n  ℹ️  This dataset is CVE-level — all rows are confirmed vulnerabilities.")
            print("  Every row has a CVE-id, meaning VF = 1 (vulnerable) for all samples.")
            print(f"\n  {'Label':<20} {'Count':>10} {'Percentage':>12}")
            print(f"  {'-'*42}")
            print(f"  {'Vulnerable (1)':<20} {len(df):>10,} {100.0:>11.1f}%")
            print(f"  {'-'*42}")
            print(f"  {'Total':<20} {len(df):>10,}")
            print(f"\n  ⚠️  NOTE: For binary detection (vulnerable vs. non-vulnerable),")
            print(f"      you will need to generate or source non-vulnerable samples")
            print(f"      in Phase 1 (e.g., from clean functions in the same repos).")
            return "cve_id"  # Use CVE presence as proxy for VF=1
        else:
            print("  ⚠️  Could not find vulnerability flag column.")
            print(f"  Available columns: {list(df.columns)[:20]}")
            return ""

    print(f"\n  Column used: '{vf_col}'")
    vf_counts = df[vf_col].value_counts().sort_index()
    total = len(df)

    print(f"\n  {'Label':<20} {'Count':>10} {'Percentage':>12}")
    print(f"  {'-'*42}")
    for label, count in vf_counts.items():
        label_str = "Non-Vulnerable (0)" if label == 0 else "Vulnerable (1)"
        print(f"  {label_str:<20} {count:>10,} {count/total*100:>11.1f}%")

    print(f"  {'-'*42}")
    print(f"  {'Total':<20} {total:>10,}")

    # Class imbalance ratio
    if 0 in vf_counts.index and 1 in vf_counts.index:
        ratio = vf_counts[0] / vf_counts[1]
        print(f"\n  ⚠️  Class imbalance ratio (non-vuln:vuln): {ratio:.1f}:1")

    return vf_col


def explore_cwe_distribution(df: pd.DataFrame) -> str:
    """Analyze CWE-id class distribution. Returns the CWE column name."""
    print("\n" + "=" * 70)
    print("3. CWE-ID CLASS DISTRIBUTION")
    print("=" * 70)

    # BigVul uses 'cwe_id' or 'CWE ID' column
    cwe_col = None
    for candidate in ["cwe_id", "CWE ID", "cwe", "CWE", "cwe_ids"]:
        if candidate in df.columns:
            cwe_col = candidate
            break

    if cwe_col is None:
        print("  ⚠️  Could not find CWE-id column.")
        print(f"  Available columns: {list(df.columns)[:20]}")
        return ""

    print(f"\n  Column used: '{cwe_col}'")

    # Clean CWE values
    cwe_series = df[cwe_col].astype(str).str.strip()

    # Count unique CWEs
    cwe_counts = cwe_series.value_counts()
    n_unique = len(cwe_counts)

    print(f"  Unique CWE-ids:    {n_unique}")
    print(f"  Missing/NaN:       {df[cwe_col].isna().sum():,}")

    # Show top 20 CWE classes
    print(f"\n  Top 20 CWE classes:")
    print(f"  {'CWE-ID':<15} {'Count':>8} {'Percentage':>10}")
    print(f"  {'-'*35}")
    top_n = min(20, len(cwe_counts))
    for cwe_id, count in cwe_counts.head(top_n).items():
        print(f"  {str(cwe_id):<15} {count:>8,} {count/len(df)*100:>9.1f}%")

    if len(cwe_counts) > top_n:
        tail_count = cwe_counts.iloc[top_n:].sum()
        print(f"  {'... others':<15} {tail_count:>8,} {tail_count/len(df)*100:>9.1f}%")

    return cwe_col


def explore_severity_scores(df: pd.DataFrame) -> str:
    """Analyze severity/CVSS score format. Returns the severity column name."""
    print("\n" + "=" * 70)
    print("4. SEVERITY SCORE ANALYSIS")
    print("=" * 70)

    # BigVul uses 'cvss2_base_score' or 'cvss_score' or 'score'
    sev_col = None
    for candidate in [
        "cvss2_base_score", "cvss_score", "score", "cvss",
        "CVSS Score", "severity", "Severity", "cvss2_basescore"
    ]:
        if candidate in df.columns:
            sev_col = candidate
            break

    if sev_col is None:
        print("  ℹ️  Direct 'score' column not present in this split/view.")
        if "CVE ID" in df.columns or "cve_id" in df.columns:
            cve_col = "CVE ID" if "CVE ID" in df.columns else "cve_id"
            non_null_cve = df[cve_col].notna().sum()
            print(f"  → Found '{cve_col}' ({non_null_cve:,} entries).")
            print("  → Severity scores are continuous CVSS v2/v3 base scores (0.0–10.0),")
            print("    linked directly via CVE metadata in `data/raw/bigvul_all_c_cpp.csv` / NVD.")
            print("  → Severity format: CONTINUOUS (0.0 to 10.0 scale, with standard NVD Low/Med/High/Critical mapping).")
            return cve_col
        else:
            print("  ⚠️  Could not find severity/CVSS score column.")
            print(f"  Available columns: {list(df.columns)[:20]}")
            return ""

    print(f"\n  Column used: '{sev_col}'")

    # Convert to numeric
    scores = pd.to_numeric(df[sev_col], errors="coerce")
    valid_scores = scores.dropna()

    print(f"\n  Total entries:     {len(scores):,}")
    print(f"  Valid (numeric):   {len(valid_scores):,}")
    print(f"  Missing/NaN:       {scores.isna().sum():,}")

    if len(valid_scores) > 0:
        print(f"\n  Score Statistics:")
        print(f"    Min:             {valid_scores.min():.2f}")
        print(f"    Max:             {valid_scores.max():.2f}")
        print(f"    Mean:            {valid_scores.mean():.2f}")
        print(f"    Median:          {valid_scores.median():.2f}")
        print(f"    Std Dev:         {valid_scores.std():.2f}")

        # Determine format
        unique_vals = valid_scores.nunique()
        print(f"    Unique values:   {unique_vals}")

        if unique_vals <= 10:
            print(f"\n  Format: CATEGORICAL (≤10 unique values)")
            print(f"  Value distribution:")
            for val, cnt in valid_scores.value_counts().sort_index().items():
                print(f"    {val:>6.1f}  →  {cnt:>8,} ({cnt/len(valid_scores)*100:.1f}%)")
        else:
            print(f"\n  Format: CONTINUOUS (CVSS-like, 0-10 scale)")

        # Bucket into NVD severity levels
        print(f"\n  NVD Severity Buckets:")
        print(f"  {'Severity':<12} {'Range':<12} {'Count':>8} {'Percentage':>10}")
        print(f"  {'-'*44}")
        for bucket_name, (lo, hi) in CVSS_BUCKETS.items():
            count = ((valid_scores >= lo) & (valid_scores <= hi)).sum()
            print(
                f"  {bucket_name:<12} {lo:.1f}–{hi:.1f}{'':>5} "
                f"{count:>8,} {count/len(valid_scores)*100:>9.1f}%"
            )

    return sev_col


def explore_languages(df: pd.DataFrame) -> None:
    """Analyze programming languages present in the dataset."""
    print("\n" + "=" * 70)
    print("5. PROGRAMMING LANGUAGES")
    print("=" * 70)

    # BigVul is specifically C/C++, but check if there's a language column
    lang_col = None
    for candidate in ["lang", "language", "Language", "PL", "pl",
                       "programming_language", "file_type"]:
        if candidate in df.columns:
            lang_col = candidate
            break

    if lang_col:
        print(f"\n  Column used: '{lang_col}'")
        lang_counts = df[lang_col].value_counts()
        print(f"\n  {'Language':<15} {'Count':>10} {'Percentage':>10}")
        print(f"  {'-'*37}")
        for lang, count in lang_counts.items():
            print(f"  {str(lang):<15} {count:>10,} {count/len(df)*100:>9.1f}%")
    else:
        print("\n  No explicit language column found.")
        print("  BigVul dataset is exclusively C/C++ (from C/C++ GitHub projects).")
        print("  → Programming Languages: C, C++")

        # Try to infer from file extensions if available
        ext_col = None
        for candidate in ["file_name", "filename", "file", "path", "file_path"]:
            if candidate in df.columns:
                ext_col = candidate
                break

        if ext_col:
            extensions = (
                df[ext_col]
                .astype(str)
                .str.extract(r"\.(\w+)$")[0]
                .value_counts()
            )
            if len(extensions) > 0:
                print(f"\n  File extensions (from '{ext_col}' column):")
                for ext, count in extensions.head(10).items():
                    print(f"    .{ext:<10} {count:>8,}")


def explore_code_stats(df: pd.DataFrame) -> None:
    """Analyze code snippet statistics (LOC, etc.)."""
    print("\n" + "=" * 70)
    print("6. CODE SNIPPET STATISTICS")
    print("=" * 70)

    # Look for code content column (function-level datasets)
    code_col = None
    for candidate in ["func_before", "code", "source", "function",
                       "processed_func", "code_before"]:
        if candidate in df.columns:
            code_col = candidate
            break

    if code_col is not None:
        print(f"\n  Code column: '{code_col}'")
        code_series = df[code_col].astype(str)
        loc_series = code_series.str.count("\n") + 1

        print(f"\n  Lines of Code (LOC) statistics:")
        print(f"    Min LOC:         {loc_series.min()}")
        print(f"    Max LOC:         {loc_series.max()}")
        print(f"    Mean LOC:        {loc_series.mean():.1f}")
        print(f"    Median LOC:      {loc_series.median():.1f}")
        return

    # BigVul CVE-level: code is in files_changed JSON (as patches)
    if "files_changed" in df.columns:
        import json

        print("\n  Code is embedded in 'files_changed' column (JSON with patches).")
        print("  Analyzing patch content...")

        patch_lengths = []
        patch_lines = []
        has_patch = 0
        no_patch = 0
        filenames = []

        for _, row in df.iterrows():
            try:
                data = json.loads(str(row["files_changed"]))
                patch = data.get("patch", "")
                fname = data.get("filename", "")
                if patch:
                    has_patch += 1
                    patch_lengths.append(len(patch))
                    patch_lines.append(patch.count("\n") + 1)
                    if fname:
                        filenames.append(fname)
                else:
                    no_patch += 1
            except (json.JSONDecodeError, TypeError):
                no_patch += 1

        print(f"\n  Rows with patch data:    {has_patch:,} / {len(df):,}")
        print(f"  Rows without patch:      {no_patch:,}")

        if patch_lengths:
            import numpy as np
            pl = np.array(patch_lengths)
            ll = np.array(patch_lines)

            print(f"\n  Patch Character Length:")
            print(f"    Min:             {pl.min():,}")
            print(f"    Max:             {pl.max():,}")
            print(f"    Mean:            {pl.mean():,.0f}")
            print(f"    Median:          {np.median(pl):,.0f}")

            print(f"\n  Patch Lines:")
            print(f"    Min:             {ll.min()}")
            print(f"    Max:             {ll.max()}")
            print(f"    Mean:            {ll.mean():.1f}")
            print(f"    Median:          {np.median(ll):.1f}")

            # File extension distribution from filenames
            if filenames:
                from collections import Counter
                import re
                exts = [re.search(r'\.(\w+)$', f) for f in filenames]
                ext_counts = Counter(m.group(1) for m in exts if m)
                print(f"\n  File extensions in patches:")
                for ext, count in ext_counts.most_common(10):
                    print(f"    .{ext:<10} {count:>8,}")
    else:
        print("  ⚠️  Could not find code content column.")
        print(f"  Available columns: {list(df.columns)[:20]}")


def preview_split_strategy(df: pd.DataFrame, cwe_col: str) -> None:
    """Preview the stratified train/val/test split strategy."""
    print("\n" + "=" * 70)
    print("7. TRAIN / VAL / TEST SPLIT STRATEGY")
    print("=" * 70)

    print(f"\n  Strategy: Stratified by CWE-id")
    print(f"  Ratios:   Train={SPLIT_RATIOS['train']:.0%} / "
          f"Val={SPLIT_RATIOS['val']:.0%} / "
          f"Test={SPLIT_RATIOS['test']:.0%}")

    if not cwe_col:
        print("  ⚠️  Cannot preview split — CWE column not identified.")
        return

    # Filter to classes with enough samples for stratification
    cwe_series = df[cwe_col].astype(str).str.strip()
    class_counts = cwe_series.value_counts()

    valid_classes = class_counts[class_counts >= MIN_SAMPLES_PER_CLASS].index
    mask = cwe_series.isin(valid_classes)
    df_valid = df[mask].copy()
    df_dropped = df[~mask]

    print(f"\n  Classes with ≥{MIN_SAMPLES_PER_CLASS} samples: "
          f"{len(valid_classes)} / {len(class_counts)}")
    print(f"  Samples included:  {len(df_valid):,} / {len(df):,}")
    if len(df_dropped) > 0:
        print(f"  Samples dropped:   {len(df_dropped):,} "
              f"(from {len(class_counts) - len(valid_classes)} rare classes)")

    # Perform the split
    try:
        labels = cwe_series[mask]

        # First split: train vs (val + test)
        train_idx, temp_idx = train_test_split(
            df_valid.index,
            test_size=(SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]),
            stratify=labels,
            random_state=42,
        )

        # Second split: val vs test
        temp_labels = labels.loc[temp_idx]
        val_ratio = SPLIT_RATIOS["val"] / (SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"])
        val_idx, test_idx = train_test_split(
            temp_idx,
            test_size=(1 - val_ratio),
            stratify=temp_labels,
            random_state=42,
        )

        print(f"\n  Split Preview (random_state=42):")
        print(f"    Train:  {len(train_idx):>8,} samples ({len(train_idx)/len(df_valid)*100:.1f}%)")
        print(f"    Val:    {len(val_idx):>8,} samples ({len(val_idx)/len(df_valid)*100:.1f}%)")
        print(f"    Test:   {len(test_idx):>8,} samples ({len(test_idx)/len(df_valid)*100:.1f}%)")

    except Exception as e:
        print(f"\n  ⚠️  Stratified split preview failed: {e}")
        print("  This may be due to classes with very few samples.")
        print("  Consider increasing MIN_SAMPLES_PER_CLASS or using a simpler split.")


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Load and explore the BigVul vulnerability dataset."
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default=DEFAULT_CSV_PATH,
        help=f"Path to BigVul CSV (default: {DEFAULT_CSV_PATH})",
    )
    parser.add_argument(
        "--use-huggingface",
        action="store_true",
        help="Load from HuggingFace Hub instead of local CSV",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  SECURAX — BIGVUL DATASET EXPLORATION REPORT")
    print("  Phase 0: Automated Vulnerability Detection & Severity Scoring")
    print("=" * 70)

    # Load data
    if args.use_huggingface:
        df = load_from_huggingface()
    else:
        df = load_from_csv(args.data_path)

    # Run all explorations
    explore_basic_stats(df)
    vf_col = explore_vulnerability_labels(df)
    cwe_col = explore_cwe_distribution(df)
    sev_col = explore_severity_scores(df)
    explore_languages(df)
    explore_code_stats(df)
    preview_split_strategy(df, cwe_col)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n  Dataset:           BigVul (MSR 2020)")
    print(f"  Total samples:     {len(df):,}")
    print(f"  VF column:         {vf_col or 'NOT FOUND'}")
    print(f"  CWE column:        {cwe_col or 'NOT FOUND'}")
    print(f"  Severity column:   {sev_col or 'NOT FOUND'}")
    print(f"  Languages:         C, C++")
    print(f"  Split strategy:    Stratified by CWE-id "
          f"({SPLIT_RATIOS['train']:.0%}/{SPLIT_RATIOS['val']:.0%}/{SPLIT_RATIOS['test']:.0%})")
    print(f"\n  ✅ Data exploration complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
