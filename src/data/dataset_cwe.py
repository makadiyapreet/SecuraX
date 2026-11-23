"""
dataset_cwe.py — Data pipeline for Phase 2 (v2) multi-class CWE classification.

V2 changes over V1:
  - Semantic CWE grouping (15 classes based on MITRE CWE-1000 hierarchy)
    instead of arbitrary "Other" bucket.
  - WeightedRandomSampler support for minority-class oversampling.
  - Multi-model tokenizer support (CodeT5 and GraphCodeBERT).

Provides:
  - BigVulCWEDataset: PyTorch Dataset returning (input_ids, attention_mask, label)
  - build_cwe_label_map_v2(): Semantic CWE grouping
  - create_cwe_splits(): Stratified 70/15/15 split
  - create_cwe_dataloaders(): DataLoaders with optional WeightedRandomSampler

Usage:
    from src.data.dataset_cwe import create_cwe_dataloaders

    train_dl, val_dl, test_dl, label_map, class_names = create_cwe_dataloaders(
        model_key="codet5", max_length=512, batch_size=8, use_oversampling=True,
    )
"""

import os
import sys
import json
import warnings
from typing import Dict, List, Tuple, Optional
from collections import Counter

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)

# ─── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

SPLIT_RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}
RANDOM_SEED = 42

# Column names in BigVul HuggingFace dataset
CODE_COL = "func_before"   # source code of the function
VUL_COL = "vul"             # 0 = non-vulnerable, 1 = vulnerable
CWE_COL = "CWE ID"          # CWE identifier string (e.g., "CWE-119")

# Minimum samples for a CWE class to get its own label (v1 compat)
MIN_CLASS_SAMPLES = 50


# ─── Semantic CWE Grouping (v2) ─────────────────────────────────────────────
#
# Based on MITRE CWE-1000 Research View parent-child hierarchy.
# Groups 84 CWEs into 15 semantically coherent classes.
#
# Design decisions:
#   - CWE-416 (UAF) KEPT SEPARATE from CWE-119 (buffer overflow)
#     because v1 showed severe confusion between them.
#   - CWE-125 (OOB Read) and CWE-787 (OOB Write) kept as own classes
#     — enough samples and distinct error types.
#   - "Other-Security" groups remaining CWEs that share a defensive
#     security theme, unlike the old incoherent "Other".
# ─────────────────────────────────────────────────────────────────────────────

CWE_SEMANTIC_GROUPS = {
    "Buffer-Overflow": [
        "CWE-119",   # Buffer overflow (class-level)
        "CWE-120",   # Classic buffer overflow
        "CWE-129",   # Improper validation of array index
    ],
    "OOB-Read": [
        "CWE-125",   # Out-of-bounds read
    ],
    "OOB-Write": [
        "CWE-787",   # Out-of-bounds write
    ],
    "Use-After-Free": [
        "CWE-416",   # Use after free
        "CWE-824",   # Access of uninitialized pointer
    ],
    "Double-Free": [
        "CWE-415",   # Double free
        "CWE-763",   # Release of invalid pointer
    ],
    "NULL-Deref": [
        "CWE-476",   # NULL pointer dereference
        "CWE-252",   # Unchecked return value
    ],
    "Integer-Issues": [
        "CWE-190",   # Integer overflow
        "CWE-191",   # Integer underflow
        "CWE-189",   # Numeric errors (class-level)
        "CWE-369",   # Divide by zero
        "CWE-682",   # Incorrect calculation
        "CWE-704",   # Incorrect type conversion
    ],
    "Input-Validation": [
        "CWE-20",    # Improper input validation (class-level)
        "CWE-74",    # Injection
        "CWE-77",    # Command injection
        "CWE-78",    # OS command injection
        "CWE-79",    # Cross-site scripting (XSS)
        "CWE-89",    # SQL injection
        "CWE-94",    # Code injection
        "CWE-134",   # Use of externally-controlled format string
        "CWE-611",   # XXE
        "CWE-918",   # SSRF
        "CWE-90",    # LDAP injection
    ],
    "Info-Exposure": [
        "CWE-200",   # Exposure of sensitive info (class-level)
        "CWE-209",   # Error message info leak
        "CWE-532",   # Info exposure through log files
    ],
    "Access-Control": [
        "CWE-264",   # Permissions, privileges (category-level)
        "CWE-269",   # Improper privilege management
        "CWE-281",   # Improper preservation of permissions
        "CWE-284",   # Improper access control (class-level)
        "CWE-285",   # Improper authorization
        "CWE-287",   # Improper authentication
        "CWE-732",   # Incorrect permission assignment
        "CWE-862",   # Missing authorization
    ],
    "Crypto-Issues": [
        "CWE-310",   # Cryptographic issues (category-level)
        "CWE-311",   # Missing encryption
        "CWE-320",   # Key management errors
        "CWE-327",   # Use of broken crypto algorithm
        "CWE-330",   # Use of insufficiently random values
        "CWE-345",   # Insufficient verification of data authenticity
        "CWE-346",   # Origin validation error
        "CWE-347",   # Improper verification of crypto signature
        "CWE-354",   # Improper validation of integrity check value
        "CWE-358",   # Improperly implemented security check
    ],
    "Resource-Mgmt": [
        "CWE-399",   # Resource management errors (class-level)
        "CWE-400",   # Uncontrolled resource consumption
        "CWE-404",   # Improper resource shutdown/release
        "CWE-770",   # Allocation without limits
        "CWE-772",   # Missing release of resource
        "CWE-834",   # Excessive iteration
        "CWE-835",   # Infinite loop
        "CWE-674",   # Uncontrolled recursion
    ],
    "Race-Condition": [
        "CWE-362",   # Race condition
    ],
    "Path-Traversal": [
        "CWE-22",    # Path traversal
        "CWE-59",    # Improper link resolution (symlink)
        "CWE-426",   # Untrusted search path
        "CWE-601",   # URL redirect to untrusted site
    ],
    "Other-Security": [
        # Security features, error handling, and remaining CWEs
        "CWE-17",    # Code (DEPRECATED category)
        "CWE-18",    # Source Code (DEPRECATED category)
        "CWE-19",    # Data handling (DEPRECATED category)
        "CWE-254",   # Security features (category)
        "CWE-388",   # Error handling (category)
        "CWE-436",   # Interpretation conflict
        "CWE-494",   # Download without integrity check
        "CWE-502",   # Deserialization of untrusted data
        "CWE-522",   # Insufficiently protected credentials
        "CWE-617",   # Reachable assertion
        "CWE-664",   # Improper control of resource
        "CWE-665",   # Improper initialization
        "CWE-668",   # Exposure of resource to wrong sphere
        "CWE-693",   # Protection mechanism failure
        "CWE-754",   # Improper check for unusual conditions
        "CWE-755",   # Improper handling of exceptional conditions
        "CWE-16",    # Configuration
        "CWE-172",   # Encoding error
        "CWE-295",   # Improper certificate validation
        "CWE-352",   # Cross-Site Request Forgery (CSRF)
        "CWE-1021",  # Improper restriction of rendered UI layers
    ],
}

# Build reverse mapping: CWE-id → group name
_CWE_TO_GROUP = {}
for group_name, cwe_list in CWE_SEMANTIC_GROUPS.items():
    for cwe_id in cwe_list:
        _CWE_TO_GROUP[cwe_id] = group_name


# ─── CWE label mapping (v2 — semantic grouping) ─────────────────────────────


def build_cwe_label_map_v2(
    df: pd.DataFrame,
) -> Tuple[Dict[str, int], List[str]]:
    """Build a CWE-id → class index mapping using semantic grouping.

    Maps every CWE-id to one of the 15 semantic groups based on
    CWE_SEMANTIC_GROUPS. Any CWE not explicitly listed falls into
    "Other-Security".

    Returns:
        (label_map, class_names)
        - label_map: {cwe_id_string: int_class_index}
        - class_names: list of group names in order
    """
    # Fixed class order (deterministic)
    class_names = list(CWE_SEMANTIC_GROUPS.keys())
    group_to_idx = {name: idx for idx, name in enumerate(class_names)}
    other_idx = group_to_idx["Other-Security"]

    # Map each CWE in the data to a group
    label_map = {}
    cwe_counts = df[CWE_COL].value_counts()
    for cwe_id in cwe_counts.index:
        group = _CWE_TO_GROUP.get(cwe_id, "Other-Security")
        label_map[cwe_id] = group_to_idx[group]

    # Print distribution
    print(f"\n  CWE Semantic Grouping (v2):")
    print(f"    Total unique CWEs in data: {len(cwe_counts)}")
    print(f"    Num semantic groups:        {len(class_names)}")
    print(f"\n    Group distribution:")
    for idx, name in enumerate(class_names):
        group_cwes = CWE_SEMANTIC_GROUPS[name]
        count = sum(cwe_counts.get(c, 0) for c in group_cwes)
        # Also count any unmapped CWEs that fell to Other-Security
        if name == "Other-Security":
            for cwe_id in cwe_counts.index:
                if cwe_id not in _CWE_TO_GROUP:
                    count += cwe_counts[cwe_id]
        n_cwes_present = sum(1 for c in group_cwes if c in cwe_counts.index)
        print(f"      [{idx:>2}] {name:<18} {count:>5} samples  "
              f"({n_cwes_present} CWEs in data)")

    return label_map, class_names


# ─── V1 compat: old "Other" bucket approach ─────────────────────────────────


def build_cwe_label_map(
    df: pd.DataFrame,
    min_samples: int = MIN_CLASS_SAMPLES,
) -> Tuple[Dict[str, int], List[str]]:
    """V1 label map (kept for backward compatibility / comparison).

    Buckets rare CWEs (<min_samples) into a single 'Other' class.
    """
    cwe_counts = df[CWE_COL].value_counts()
    keep_cwes = sorted(cwe_counts[cwe_counts >= min_samples].index.tolist())
    class_names = keep_cwes + ["Other"]
    label_map = {cwe: idx for idx, cwe in enumerate(keep_cwes)}
    other_idx = len(keep_cwes)
    for cwe in cwe_counts.index:
        if cwe not in label_map:
            label_map[cwe] = other_idx
    return label_map, class_names


# ─── Dataset class ───────────────────────────────────────────────────────────


class BigVulCWEDataset(Dataset):
    """Dataset for multi-class CWE classification.

    Supports original BigVul data and tier-specific processed CSVs.
    Uses _cwe_label when available, otherwise maps CWE IDs through
    label_map.
    """

    def __init__(
        self,
        dataframe: pd.DataFrame,
        tokenizer,
        label_map: Dict[str, int],
        max_length: int = 256,
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length

        # Find the source-code column.
        if CODE_COL in dataframe.columns:
            code_col = CODE_COL
        else:
            raise ValueError(
                f"Missing source-code column '{CODE_COL}'. "
                f"Available columns: {list(dataframe.columns)}"
            )

        self.codes = dataframe[code_col].fillna("").astype(str).tolist()

        # Prefer the semantic labels prepared by the tier data loader.
        if "_cwe_label" in dataframe.columns:
            self.labels = dataframe["_cwe_label"].astype(int).tolist()
        else:
            # Fall back to mapping original CWE IDs.
            if CWE_COL in dataframe.columns:
                cwe_col = CWE_COL
            elif "cwe_id" in dataframe.columns:
                cwe_col = "cwe_id"
            elif "CWE ID" in dataframe.columns:
                cwe_col = "CWE ID"
            else:
                raise ValueError(
                    "No CWE column found. Expected '_cwe_label', "
                    f"'{CWE_COL}', or 'cwe_id'. Columns: "
                    f"{list(dataframe.columns)}"
                )

            def normalize_cwe(value):
                if pd.isna(value):
                    return ""
                value = str(value).strip().upper()
                if value.isdigit():
                    return f"CWE-{value}"
                return value

            normalized_map = {
                normalize_cwe(key): int(value)
                for key, value in label_map.items()
            }

            self.labels = []
            missing_cwes = set()

            for cwe in dataframe[cwe_col]:
                normalized = normalize_cwe(cwe)

                if normalized not in normalized_map:
                    missing_cwes.add(normalized)
                    self.labels.append(-1)
                else:
                    self.labels.append(normalized_map[normalized])

            if missing_cwes:
                raise ValueError(
                    "CWE IDs missing from label_map: "
                    f"{sorted(missing_cwes)[:20]}"
                )

        if len(self.codes) != len(self.labels):
            raise ValueError(
                "Number of code samples does not match number of labels."
            )

        if any(label < 0 for label in self.labels):
            raise ValueError("Dataset contains negative class labels.")

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        code = self.codes[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            code,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.long),
        }

# ─── Data loading & splitting ───────────────────────────────────────────────


def load_vulnerable_dataframe() -> pd.DataFrame:
    """Load BigVul, filter to vulnerable samples with valid CWE IDs."""
    from datasets import load_dataset

    print("Loading BigVul from HuggingFace Hub (benjis/bigvul)...")
    ds = load_dataset("benjis/bigvul")

    dfs = []
    for split_name in ["train", "validation", "test"]:
        if split_name in ds:
            split_df = ds[split_name].to_pandas()
            dfs.append(split_df)
            print(f"  {split_name:>12}: {len(split_df):>8,} samples")

    df = pd.concat(dfs, ignore_index=True)
    print(f"  {'Total':>12}: {len(df):>8,} samples")

    # Filter to vulnerable samples only
    df = df[df[VUL_COL] == 1].copy()
    print(f"  {'Vulnerable':>12}: {len(df):>8,} samples")

    # Drop rows with missing code or CWE ID
    df = df.dropna(subset=[CODE_COL, CWE_COL]).reset_index(drop=True)
    # Also drop empty strings
    df = df[df[CWE_COL].str.strip().astype(bool)].reset_index(drop=True)
    print(f"  {'With CWE':>12}: {len(df):>8,} samples")

    return df


def create_cwe_splits(
    df: pd.DataFrame = None,
    use_semantic_groups: bool = True,
    min_class_samples: int = MIN_CLASS_SAMPLES,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, int], List[str]]:
    """Create stratified train/val/test splits for CWE classification.

    Args:
        df: Optional pre-loaded DataFrame (vulnerable samples with CWE IDs)
        use_semantic_groups: If True, use v2 semantic grouping; else v1 bucketing
        min_class_samples: Min samples for v1 bucketing (ignored if semantic)

    Returns:
        (train_df, val_df, test_df, label_map, class_names)
    """
    if df is None:
        df = load_vulnerable_dataframe()

    # Build label map
    if use_semantic_groups:
        label_map, class_names = build_cwe_label_map_v2(df)
    else:
        label_map, class_names = build_cwe_label_map(df, min_class_samples)

    # Create integer labels for stratification
    df = df.copy()
    df["_cwe_label"] = df[CWE_COL].map(label_map)

    # Stratified split by CWE group
    labels = df["_cwe_label"]

    # First: train vs (val + test)
    train_df, temp_df = train_test_split(
        df,
        test_size=(SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]),
        stratify=labels,
        random_state=RANDOM_SEED,
    )

    # Second: val vs test
    temp_labels = temp_df["_cwe_label"]
    val_ratio = SPLIT_RATIOS["val"] / (SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"])
    val_df, test_df = train_test_split(
        temp_df,
        test_size=(1 - val_ratio),
        stratify=temp_labels,
        random_state=RANDOM_SEED,
    )

    # Reset indices
    for split_df in [train_df, val_df, test_df]:
        split_df.reset_index(drop=True, inplace=True)

    # Print stats
    print(f"\n  Splits (CWE classification — vulnerable samples only):")
    for name, split_df in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        n_total = len(split_df)
        class_dist = split_df["_cwe_label"].value_counts()
        print(f"    {name:>5}: {n_total:>6,} samples  "
              f"(classes with samples: {len(class_dist)})")

    return train_df, val_df, test_df, label_map, class_names


# ─── WeightedRandomSampler builder ──────────────────────────────────────────


def build_weighted_sampler(dataset: BigVulCWEDataset) -> WeightedRandomSampler:
    """Create a WeightedRandomSampler for minority-class oversampling.

    Each sample gets weight = 1 / count_of_its_class, so rare classes
    are sampled more frequently.

    Args:
        dataset: BigVulCWEDataset instance

    Returns:
        WeightedRandomSampler
    """
    labels = dataset.labels
    class_counts = Counter(labels)
    n_classes = len(class_counts)

    # Weight per sample = 1 / class_count
    sample_weights = [1.0 / class_counts[label] for label in labels]
    sample_weights = torch.DoubleTensor(sample_weights)

    # num_samples = total dataset length (one full pass, but resampled)
    sampler = WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(labels),
        replacement=True,
    )

    print(f"\n  WeightedRandomSampler built:")
    print(f"    Num samples: {len(labels)}")
    print(f"    Classes: {n_classes}")
    print(f"    Min class count: {min(class_counts.values())}")
    print(f"    Max class count: {max(class_counts.values())}")

    return sampler


# ─── DataLoader factory ─────────────────────────────────────────────────────


def create_cwe_dataloaders(
    model_key: str = "codet5",
    max_length: int = 512,
    batch_size: int = 8,
    num_workers: int = 0,
    df: pd.DataFrame = None,
    use_semantic_groups: bool = True,
    use_oversampling: bool = True,
    min_class_samples: int = MIN_CLASS_SAMPLES,
) -> Tuple[DataLoader, DataLoader, DataLoader, Dict[str, int], List[str]]:
    """Build train/val/test DataLoaders for CWE classification.

    Args:
        model_key: "codet5" or "graphcodebert"
        max_length: Max token sequence length
        batch_size: Batch size for DataLoaders
        num_workers: Number of worker processes
        df: Optional pre-loaded DataFrame
        use_semantic_groups: Use v2 semantic grouping (True) or v1 bucketing
        use_oversampling: Use WeightedRandomSampler for training
        min_class_samples: Min samples for v1 bucketing

    Returns:
        (train_loader, val_loader, test_loader, label_map, class_names)
    """
    from src.data.dataset import get_tokenizer

    grouping = "semantic (v2)" if use_semantic_groups else f"bucketing (v1, min={min_class_samples})"
    print(f"\n{'='*60}")
    print(f"  Creating CWE DataLoaders")
    print(f"  Model:        {model_key}")
    print(f"  Max length:   {max_length}, Batch size: {batch_size}")
    print(f"  Grouping:     {grouping}")
    print(f"  Oversampling: {use_oversampling}")
    print(f"{'='*60}\n")

    # Load tokenizer
    tokenizer = get_tokenizer(model_key)
    print(f"  Tokenizer: {type(tokenizer).__name__}")

    # Create splits
    print("\n  Creating stratified splits (by CWE group)...")
    train_df, val_df, test_df, label_map, class_names = create_cwe_splits(
        df, use_semantic_groups=use_semantic_groups,
        min_class_samples=min_class_samples,
    )

    # Create datasets
    print("\n  Building PyTorch Datasets...")
    train_ds = BigVulCWEDataset(train_df, tokenizer, label_map, max_length)
    val_ds = BigVulCWEDataset(val_df, tokenizer, label_map, max_length)
    test_ds = BigVulCWEDataset(test_df, tokenizer, label_map, max_length)

    # pin_memory only on CUDA
    use_pin_memory = torch.cuda.is_available()

    # Build train loader with optional oversampling
    if use_oversampling:
        sampler = build_weighted_sampler(train_ds)
        train_loader = DataLoader(
            train_ds, batch_size=batch_size, sampler=sampler,
            num_workers=num_workers, pin_memory=use_pin_memory, drop_last=False,
        )
    else:
        train_loader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True,
            num_workers=num_workers, pin_memory=use_pin_memory, drop_last=False,
        )

    val_loader = DataLoader(
        val_ds, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=use_pin_memory,
    )
    test_loader = DataLoader(
        test_ds, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=use_pin_memory,
    )

    print(f"\n  ✅ CWE DataLoaders ready:")
    print(f"     Train: {len(train_loader):>6} batches ({len(train_ds):>6,} samples)")
    print(f"     Val:   {len(val_loader):>6} batches ({len(val_ds):>6,} samples)")
    print(f"     Test:  {len(test_loader):>6} batches ({len(test_ds):>6,} samples)")
    print(f"     Classes: {len(class_names)}")

    return train_loader, val_loader, test_loader, label_map, class_names


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    train_dl, val_dl, test_dl, lmap, cnames = create_cwe_dataloaders(
        model_key="codet5", use_semantic_groups=True, use_oversampling=True,
    )

    # Smoke test
    print("\n  Smoke test — first training batch:")
    batch = next(iter(train_dl))
    for k, v in batch.items():
        print(f"    {k}: shape={v.shape}, dtype={v.dtype}")
    print(f"    Label range: [{batch['labels'].min()}, {batch['labels'].max()}]")
    print(f"\n  ✅ CWE data pipeline v2 smoke test passed.")
