"""
dataset_multilang.py — Multi-tier data pipeline for the revised Phase 1+.

Loads pre-built CSV splits from data/processed/<tier>/<task>/{train,val,test}.csv
(created by Phase 0.5's audit_multilang.py) and returns PyTorch DataLoaders.

Supports:
  - Tier 1  : dedicated language splits (e.g. tier1_c_cpp)
  - Tier 2  : per-language splits (e.g. tier2_python)
  - Tier 3  : shared model splits with <LANG=xx> token prepended

Usage:
    from src.data.dataset_multilang import create_tier_dataloaders

    train_dl, val_dl, test_dl, meta = create_tier_dataloaders(
        tier="tier1_c_cpp",
        task="vf",
        model_name="codet5",
        max_length=512,
        batch_size=32,
    )
"""

import os
import sys
import json
import warnings
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader

warnings.filterwarnings("ignore", category=FutureWarning)

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")


# ─── Constants ───────────────────────────────────────────────────────────────

CODE_COL = "func_before"
LABEL_COL = "vul"
CWE_COL = "cwe_id"
CVSS_COL = "cvss_score"
LANG_TOKEN_COL = "lang_token"


MODEL_TOKENIZER_MAP = {
    "codet5": {
        "model_name": "Salesforce/codet5-base",
        "tokenizer_class": "RobertaTokenizer",
        "use_fast": False,
    },

    "graphcodebert": {
        "model_name": "microsoft/graphcodebert-base",
        "tokenizer_class": "AutoTokenizer",
        "use_fast": True,
    },

    "vulberta": {
        "model_name": "claudios/VulBERTa-MLP-VulDeePecker",
        "tokenizer_class": "AutoTokenizer",
        "use_fast": True,
    },
}


# ─── Dataset ─────────────────────────────────────────────────────────────────


class MultiTierDataset(Dataset):
    """PyTorch Dataset for multi-tier vulnerability detection.

    Each sample returns:
        input_ids      : torch.LongTensor [max_length]
        attention_mask : torch.LongTensor [max_length]
        labels         : torch.LongTensor scalar (0 or 1 for VF task)
    """

    def __init__(
        self,
        dataframe: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
        task: str = "vf",
        use_lang_tokens: bool = False,
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.task = task
        self.use_lang_tokens = use_lang_tokens

        # Code column
        self.codes = dataframe[CODE_COL].astype(str).tolist()

        # Labels depend on task
        if task == "vf":
            self.labels = dataframe[LABEL_COL].astype(int).tolist()

        elif task == "cwe":
            self.labels = dataframe["cwe_label"].astype(int).tolist()

        elif task == "severity":
            self.labels = dataframe[CVSS_COL].astype(float).tolist()

        else:
            self.labels = dataframe[LABEL_COL].astype(int).tolist()

        # Language tokens for Tier 3
        if use_lang_tokens and LANG_TOKEN_COL in dataframe.columns:
            self.lang_tokens = dataframe[LANG_TOKEN_COL].astype(str).tolist()
        else:
            self.lang_tokens = None

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:

        code = self.codes[idx]

        # Prepend language token for Tier 3 shared models
        if self.lang_tokens is not None:
            code = f"{self.lang_tokens[idx]} {code}"

        encoding = self.tokenizer(
            code,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        item = {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
        }

        if self.task == "severity":
            item["labels"] = torch.tensor(
                self.labels[idx],
                dtype=torch.float32
            )
        else:
            item["labels"] = torch.tensor(
                self.labels[idx],
                dtype=torch.long
            )

        return item


# ─── Tokenizer ───────────────────────────────────────────────────────────────


def get_tokenizer(
    model_key: str,
    add_lang_tokens: bool = False
):
    """Load the tokenizer for a given model key.

    If add_lang_tokens=True, adds <LANG=xx> special tokens for Tier 3.
    """

    if model_key not in MODEL_TOKENIZER_MAP:
        raise ValueError(
            f"Unknown model key '{model_key}'. "
            f"Choose from: {list(MODEL_TOKENIZER_MAP.keys())}"
        )

    cfg = MODEL_TOKENIZER_MAP[model_key]

    from transformers import RobertaTokenizer, AutoTokenizer

    # ─────────────────────────────────────────────
    # CodeT5
    # ─────────────────────────────────────────────

    if cfg["tokenizer_class"] == "RobertaTokenizer":

        tokenizer = RobertaTokenizer.from_pretrained(
            cfg["model_name"],
            use_fast=cfg["use_fast"]
        )

    # ─────────────────────────────────────────────
    # GraphCodeBERT / VulBERTa
    # ─────────────────────────────────────────────

    else:

        tokenizer = AutoTokenizer.from_pretrained(
            cfg["model_name"],
            use_fast=cfg["use_fast"],

            # IMPORTANT:
            # VulBERTa repository contains custom code.
            # This allows Transformers to execute that code.
            trust_remote_code=True
        )

    # ─────────────────────────────────────────────
    # Add language tokens for Tier 3
    # ─────────────────────────────────────────────

    if add_lang_tokens:

        lang_tokens = [
            "<LANG=c>",
            "<LANG=c++>",
            "<LANG=python>",
            "<LANG=java>",
            "<LANG=javascript>",
            "<LANG=php>",
            "<LANG=go>",
            "<LANG=c#>",
            "<LANG=ruby>",
            "<LANG=rust>",
            "<LANG=typescript>",
            "<LANG=kotlin>",
            "<LANG=swift>",
        ]

        num_added = tokenizer.add_special_tokens(
            {
                "additional_special_tokens": lang_tokens
            }
        )

        if num_added > 0:
            print(
                f"  Added {num_added} language tokens to tokenizer"
            )

    return tokenizer


# ─── DataLoader factory ─────────────────────────────────────────────────────


def load_tier_split(
    tier: str,
    task: str,
    split: str,
) -> pd.DataFrame:
    """Load a single split CSV for a given tier and task.

    Args:
        tier  : e.g. 'tier1_c_cpp', 'tier2_python', 'tier3_shared'
        task  : 'vf', 'cwe', 'severity', 'repair'
        split : 'train', 'val', 'test'
    """

    csv_path = os.path.join(
        PROCESSED_DIR,
        tier,
        task,
        f"{split}.csv"
    )

    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Split file not found: {csv_path}\n"
            f"Run Phase 0.5 first: "
            f"python src/data/audit_multilang.py"
        )

    df = pd.read_csv(
        csv_path,
        low_memory=False
    )

    return df


def create_tier_dataloaders(
    tier: str,
    task: str = "vf",
    model_name: str = "codet5",
    max_length: int = 512,
    batch_size: int = 32,
    num_workers: int = 0,
    add_lang_tokens: bool = False,
    max_samples: int = None,
) -> Tuple[
    DataLoader,
    DataLoader,
    DataLoader,
    Dict
]:
    """Create train/val/test DataLoaders for a specific tier and task.

    Args:
        tier           : 'tier1_c_cpp', 'tier2_python', 'tier3_shared', etc.
        task           : 'vf', 'cwe', 'severity', 'repair'
        model_name     : 'codet5', 'graphcodebert', or 'vulberta'
        max_length     : max token length
        batch_size     : batch size
        num_workers    : dataloader workers
        add_lang_tokens: whether to add <LANG=xx> special tokens (for Tier 3)

    Returns:
        (train_loader, val_loader, test_loader, metadata_dict)
    """

    use_lang_tokens = (
        "tier3" in tier
        or add_lang_tokens
    )

    print(f"\n{'=' * 60}")

    print(
        f"  Loading data: "
        f"tier={tier}, task={task}, model={model_name}"
    )

    print(
        f"  Max length: {max_length}, "
        f"Batch size: {batch_size}"
    )

    print(
        f"  Lang tokens: {use_lang_tokens}"
    )

    print(f"{'=' * 60}\n")

    # ─────────────────────────────────────────────
    # Load tokenizer
    # ─────────────────────────────────────────────

    tokenizer = get_tokenizer(
        model_name,
        add_lang_tokens=use_lang_tokens
    )

    # ─────────────────────────────────────────────
    # Load train / validation / test splits
    # ─────────────────────────────────────────────

    train_df = load_tier_split(
        tier,
        task,
        "train"
    )

    val_df = load_tier_split(
        tier,
        task,
        "val"
    )

    test_df = load_tier_split(
        tier,
        task,
        "test"
    )

    # ─────────────────────────────────────────────
    # Subsample training data if max_samples is set
    # ─────────────────────────────────────────────

    if max_samples and len(train_df) > max_samples:

        print(
            f"  ⚡ Subsampling train: "
            f"{len(train_df):,} → {max_samples:,} "
            f"(stratified)"
        )

        if (
            task == "vf"
            and LABEL_COL in train_df.columns
        ):

            from sklearn.model_selection import train_test_split

            train_df, _ = train_test_split(
                train_df,
                train_size=max_samples,
                stratify=train_df[LABEL_COL],
                random_state=42
            )

        else:

            train_df = train_df.sample(
                n=max_samples,
                random_state=42
            )

    # ─────────────────────────────────────────────
    # Print dataset information
    # ─────────────────────────────────────────────

    for name, df in [
        ("Train", train_df),
        ("Val", val_df),
        ("Test", test_df)
    ]:

        print(
            f"  {name:>5}: "
            f"{len(df):>8,} samples"
        )

        if (
            task == "vf"
            and LABEL_COL in df.columns
        ):

            n_vuln = df[LABEL_COL].sum()

            print(
                f"         "
                f"(vuln: {n_vuln:,} = "
                f"{n_vuln / len(df) * 100:.1f}%)"
            )

    # ─────────────────────────────────────────────
    # Build datasets
    # ─────────────────────────────────────────────

    train_ds = MultiTierDataset(
        train_df,
        tokenizer,
        max_length,
        task,
        use_lang_tokens
    )

    val_ds = MultiTierDataset(
        val_df,
        tokenizer,
        max_length,
        task,
        use_lang_tokens
    )

    test_ds = MultiTierDataset(
        test_df,
        tokenizer,
        max_length,
        task,
        use_lang_tokens
    )

    # ─────────────────────────────────────────────
    # Pin memory
    # ─────────────────────────────────────────────

    pin_memory = torch.cuda.is_available()

    # ─────────────────────────────────────────────
    # Train DataLoader
    # ─────────────────────────────────────────────

    train_loader = DataLoader(
        train_ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        pin_memory=pin_memory,
        drop_last=False,
    )

    # ─────────────────────────────────────────────
    # Validation DataLoader
    # ─────────────────────────────────────────────

    val_loader = DataLoader(
        val_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=pin_memory,
    )

    # ─────────────────────────────────────────────
    # Test DataLoader
    # ─────────────────────────────────────────────

    test_loader = DataLoader(
        test_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=pin_memory,
    )

    # ─────────────────────────────────────────────
    # Metadata
    # ─────────────────────────────────────────────

    meta = {
        "tier": tier,
        "task": task,
        "model_name": model_name,
        "max_length": max_length,
        "train_samples": len(train_ds),
        "val_samples": len(val_ds),
        "test_samples": len(test_ds),
        "use_lang_tokens": use_lang_tokens,
        "vocab_size": len(tokenizer),
    }

    # ─────────────────────────────────────────────
    # Compute class weights for VF task
    # ─────────────────────────────────────────────

    if task == "vf":

        all_labels = (
            train_df[LABEL_COL]
            .astype(int)
            .values
        )

        from src.models.modules import get_class_weights

        meta["class_weights"] = get_class_weights(
            all_labels,
            num_classes=2,
            clamp_factor=10.0
        )

        meta["vuln_ratio"] = float(
            all_labels.mean()
        )

    # ─────────────────────────────────────────────
    # Final information
    # ─────────────────────────────────────────────

    print("\n  ✅ DataLoaders ready")

    print(
        f"     Train: "
        f"{len(train_loader):>6} batches"
    )

    print(
        f"     Val:   "
        f"{len(val_loader):>6} batches"
    )

    print(
        f"     Test:  "
        f"{len(test_loader):>6} batches"
    )

    return (
        train_loader,
        val_loader,
        test_loader,
        meta
    )


# ─── Manifest utilities ─────────────────────────────────────────────────────


def load_manifest() -> Dict:
    """Load the Phase 0.5 data manifest."""

    manifest_path = os.path.join(
        PROCESSED_DIR,
        "manifest.json"
    )

    if not os.path.exists(manifest_path):

        raise FileNotFoundError(
            f"Manifest not found: {manifest_path}\n"
            f"Run Phase 0.5 first: "
            f"python src/data/audit_multilang.py"
        )

    with open(
        manifest_path,
        "r"
    ) as f:

        return json.load(f)


def get_available_tiers(
    task: str = "vf"
) -> list:
    """List all tiers that have data for a given task."""

    manifest = load_manifest()

    tiers = []

    for tier_key, tier_info in manifest.get(
        "splits",
        {}
    ).items():

        tasks = tier_info.get(
            "tasks",
            {}
        )

        if (
            task in tasks
            and not tasks[task].get(
                "skipped",
                False
            )
        ):

            tiers.append(tier_key)

    return tiers


# ─── CLI ─────────────────────────────────────────────────────────────────────


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(
        description="Test multi-tier data pipeline."
    )

    parser.add_argument(
        "--tier",
        type=str,
        required=True,
        help="Tier key (e.g. tier1_c_cpp, tier2_python)"
    )

    parser.add_argument(
        "--task",
        type=str,
        default="vf",
        choices=[
            "vf",
            "cwe",
            "severity",
            "repair"
        ]
    )

    parser.add_argument(
        "--model",
        type=str,
        default="codet5",
        choices=[
            "codet5",
            "graphcodebert",
            "vulberta"
        ]
    )

    parser.add_argument(
        "--max-length",
        type=int,
        default=512
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=16
    )

    args = parser.parse_args()

    train_dl, val_dl, test_dl, meta = (
        create_tier_dataloaders(
            tier=args.tier,
            task=args.task,
            model_name=args.model,
            max_length=args.max_length,
            batch_size=args.batch_size,
        )
    )

    # ─────────────────────────────────────────────
    # Smoke test
    # ─────────────────────────────────────────────

    print(
        "\n  Smoke test — "
        "first training batch:"
    )

    batch = next(
        iter(train_dl)
    )

    for k, v in batch.items():

        print(
            f"    {k}: "
            f"shape={v.shape}, "
            f"dtype={v.dtype}"
        )

    print(
        "\n  ✅ Multi-tier data pipeline "
        "smoke test passed."
    )