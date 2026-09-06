"""
dataset.py — Data pipeline for Phase 1 binary vulnerability detection.

Provides:
  - BigVulBinaryDataset: PyTorch Dataset that tokenizes BigVul code snippets
    for CodeT5 or GraphCodeBERT and returns (input_ids, attention_mask, label).
  - create_splits(): Load BigVul from HuggingFace, perform stratified 70/15/15
    split by `vul` label, and return DataFrames.
  - create_dataloaders(): Build train/val/test DataLoaders ready for training.

Usage:
    from src.data.dataset import create_dataloaders

    train_dl, val_dl, test_dl = create_dataloaders(
        model_name="codet5",   # or "graphcodebert"
        max_length=512,
        batch_size=16,
    )
"""

import os
import sys
import hashlib
import warnings
from typing import Dict, Tuple

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)

# ─── Constants ───────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

SPLIT_RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}
RANDOM_SEED = 42

# Tokenizer mapping
MODEL_TOKENIZER_MAP = {
    "codet5": {
        "model_name": "Salesforce/codet5-base",
        "tokenizer_class": "RobertaTokenizer",
        "use_fast": False,   # required for transformers v5.x compat
    },
    "graphcodebert": {
        "model_name": "microsoft/graphcodebert-base",
        "tokenizer_class": "AutoTokenizer",
        "use_fast": True,
    },
}

# Column names in BigVul HuggingFace dataset
CODE_COL = "func_before"   # source code of the function
LABEL_COL = "vul"           # 0 = non-vulnerable, 1 = vulnerable


# ─── Dataset class ───────────────────────────────────────────────────────────


class BigVulBinaryDataset(Dataset):
    """PyTorch Dataset for binary vulnerability detection on BigVul.

    Each sample returns:
        input_ids      : torch.LongTensor [max_length]
        attention_mask : torch.LongTensor [max_length]
        labels         : torch.LongTensor scalar (0 or 1)
    """

    def __init__(
        self,
        dataframe: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
    ):
        self.codes = dataframe[CODE_COL].astype(str).tolist()
        self.labels = dataframe[LABEL_COL].astype(int).tolist()
        self.tokenizer = tokenizer
        self.max_length = max_length

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


# ─── Tokenizer loader ───────────────────────────────────────────────────────


def get_tokenizer(model_key: str):
    """Load the appropriate tokenizer for a model key ('codet5' or 'graphcodebert')."""
    if model_key not in MODEL_TOKENIZER_MAP:
        raise ValueError(
            f"Unknown model key '{model_key}'. Choose from: {list(MODEL_TOKENIZER_MAP.keys())}"
        )

    cfg = MODEL_TOKENIZER_MAP[model_key]

    from transformers import RobertaTokenizer, AutoTokenizer

    if cfg["tokenizer_class"] == "RobertaTokenizer":
        tokenizer = RobertaTokenizer.from_pretrained(
            cfg["model_name"], use_fast=cfg["use_fast"]
        )
    else:
        tokenizer = AutoTokenizer.from_pretrained(
            cfg["model_name"], use_fast=cfg["use_fast"]
        )

    return tokenizer


# ─── Data splitting ──────────────────────────────────────────────────────────


def load_bigvul_dataframe() -> pd.DataFrame:
    """Load the full BigVul dataset from HuggingFace and combine all splits."""
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

    # Validate required columns
    for col in [CODE_COL, LABEL_COL]:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' not found. Columns: {list(df.columns)}")

    # Drop rows with missing code
    n_before = len(df)
    df = df.dropna(subset=[CODE_COL]).reset_index(drop=True)
    if len(df) < n_before:
        print(f"  Dropped {n_before - len(df)} rows with missing code.")

    return df


def create_splits(
    df: pd.DataFrame = None,
    max_samples: int = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Create stratified train/val/test splits by vulnerability label.

    Args:
        df: Optional pre-loaded DataFrame
        max_samples: If set, subsample the dataset (stratified) to this many
                     total samples before splitting. Useful for faster
                     training on large datasets.

    Returns:
        (train_df, val_df, test_df)
    """
    if df is None:
        df = load_bigvul_dataframe()

    # Optional subsampling (stratified to preserve class ratio)
    if max_samples is not None and max_samples < len(df):
        print(f"  Subsampling: {len(df):,} → {max_samples:,} samples (stratified)")
        df, _ = train_test_split(
            df,
            train_size=max_samples,
            stratify=df[LABEL_COL].astype(int),
            random_state=RANDOM_SEED,
        )
        df = df.reset_index(drop=True)

    labels = df[LABEL_COL].astype(int)

    # First split: train vs (val + test)
    train_df, temp_df = train_test_split(
        df,
        test_size=(SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]),
        stratify=labels,
        random_state=RANDOM_SEED,
    )

    # Second split: val vs test (50/50 of the temp set)
    temp_labels = temp_df[LABEL_COL].astype(int)
    val_ratio = SPLIT_RATIOS["val"] / (SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"])
    val_df, test_df = train_test_split(
        temp_df,
        test_size=(1 - val_ratio),
        stratify=temp_labels,
        random_state=RANDOM_SEED,
    )

    # Reset indices
    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    # Print stats
    for name, split_df in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        n_vuln = split_df[LABEL_COL].sum()
        n_total = len(split_df)
        print(f"  {name:>5}: {n_total:>8,} samples  "
              f"(vuln: {n_vuln:>6,} = {n_vuln/n_total*100:.1f}%)")

    return train_df, val_df, test_df


# ─── DataLoader factory ─────────────────────────────────────────────────────


def create_dataloaders(
    model_name: str = "codet5",
    max_length: int = 512,
    batch_size: int = 16,
    num_workers: int = 0,
    df: pd.DataFrame = None,
    max_samples: int = None,
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """Build train/val/test DataLoaders for binary vulnerability detection.

    Args:
        model_name: 'codet5' or 'graphcodebert'
        max_length: Max token sequence length (default 512)
        batch_size: Batch size for DataLoaders
        num_workers: Number of worker processes for data loading
        df: Optional pre-loaded DataFrame (skips HuggingFace download)
        max_samples: If set, subsample the dataset to this total size

    Returns:
        (train_loader, val_loader, test_loader)
    """
    print(f"\n{'='*60}")
    print(f"  Creating DataLoaders for: {model_name}")
    print(f"  Max length: {max_length}, Batch size: {batch_size}")
    if max_samples:
        print(f"  Max samples: {max_samples:,}")
    print(f"{'='*60}\n")

    # Load tokenizer
    tokenizer = get_tokenizer(model_name)
    print(f"  Tokenizer: {type(tokenizer).__name__}")
    print(f"  Vocab size: {tokenizer.vocab_size:,}")

    # Create splits
    print("\n  Creating stratified splits (by vul label)...")
    train_df, val_df, test_df = create_splits(df, max_samples=max_samples)

    # Create datasets
    print("\n  Building PyTorch Datasets...")
    train_ds = BigVulBinaryDataset(train_df, tokenizer, max_length)
    val_ds = BigVulBinaryDataset(val_df, tokenizer, max_length)
    test_ds = BigVulBinaryDataset(test_df, tokenizer, max_length)

    # pin_memory only works on CUDA, not MPS
    use_pin_memory = torch.cuda.is_available()

    # Create dataloaders
    train_loader = DataLoader(
        train_ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        pin_memory=use_pin_memory,
        drop_last=False,
    )
    val_loader = DataLoader(
        val_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=use_pin_memory,
    )
    test_loader = DataLoader(
        test_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=use_pin_memory,
    )

    print(f"\n  ✅ DataLoaders ready:")
    print(f"     Train: {len(train_loader):>6} batches ({len(train_ds):>8,} samples)")
    print(f"     Val:   {len(val_loader):>6} batches ({len(val_ds):>8,} samples)")
    print(f"     Test:  {len(test_loader):>6} batches ({len(test_ds):>8,} samples)")

    return train_loader, val_loader, test_loader


# ─── CLI ─────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test the BigVul data pipeline.")
    parser.add_argument(
        "--model", type=str, default="codet5",
        choices=["codet5", "graphcodebert"],
        help="Model to tokenize for (default: codet5)",
    )
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--batch-size", type=int, default=16)
    args = parser.parse_args()

    train_dl, val_dl, test_dl = create_dataloaders(
        model_name=args.model,
        max_length=args.max_length,
        batch_size=args.batch_size,
    )

    # Smoke test: grab one batch
    print("\n  Smoke test — first training batch:")
    batch = next(iter(train_dl))
    for k, v in batch.items():
        print(f"    {k}: shape={v.shape}, dtype={v.dtype}")

    print("\n  ✅ Data pipeline smoke test passed.")
