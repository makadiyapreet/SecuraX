"""
dataset_severity.py — Phase 3: Severity Score Dataset & DataLoaders.

Loads CVSS severity splits (0–10 continuous) for regression training.
Supports per-tier loading and a combined cross-tier shared dataset.

Usage:
    from src.data.dataset_severity import create_severity_dataloaders

    # Per-tier
    train_dl, val_dl, test_dl, meta = create_severity_dataloaders(
        tier="tier1_c_cpp", model_name="codet5", max_length=512, batch_size=32
    )

    # Shared across all tiers (Approach C)
    train_dl, val_dl, test_dl, meta = create_severity_dataloaders(
        tier="all_shared", model_name="codet5", max_length=512, batch_size=32,
        add_lang_tokens=True
    )
"""

import os
import sys
import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.data.dataset_multilang import get_tokenizer, MODEL_TOKENIZER_MAP

# ─── Constants ───────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

TIER_DIRS = {
    "tier1_c_cpp": os.path.join(DATA_DIR, "tier1_c_cpp", "severity"),
    "tier2_cpp": os.path.join(DATA_DIR, "tier2_cpp", "severity"),
    "tier2_python": os.path.join(DATA_DIR, "tier2_python", "severity"),
    "tier2_php": os.path.join(DATA_DIR, "tier2_php", "severity"),
    "tier3_shared": os.path.join(DATA_DIR, "tier3_shared", "severity"),
}

# Language tokens for shared model (Approach C)
LANG_TOKEN_MAP = {
    "C": "<LANG=c>",
    "C++": "<LANG=cpp>",
    "Python": "<LANG=py>",
    "PHP": "<LANG=php>",
    "Go": "<LANG=go>",
    "Java": "<LANG=java>",
    "JavaScript": "<LANG=js>",
    "Ruby": "<LANG=rb>",
    "TypeScript": "<LANG=ts>",
    "JSON": "<LANG=json>",
    "Other": "<LANG=other>",
}


# ─── Dataset ─────────────────────────────────────────────────────────────────


class SeverityDataset(Dataset):
    """Dataset for CVSS severity regression (0–10 continuous).

    Each sample returns:
        input_ids      : tokenized source code (int64)
        attention_mask : attention mask (int64)
        severity       : CVSS score (float32)
    """

    def __init__(
        self,
        dataframe: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
        add_lang_tokens: bool = False,
        normalize_target: bool = True,
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.add_lang_tokens = add_lang_tokens
        self.normalize_target = normalize_target  # Scale 0-10 → 0-1 for training

        # Extract code and scores
        self.codes = dataframe["func_before"].fillna("").tolist()
        self.scores = dataframe["cvss_score"].astype(float).tolist()

        # Language tokens
        if add_lang_tokens and "language" in dataframe.columns:
            self.langs = dataframe["language"].fillna("Other").tolist()
        elif add_lang_tokens and "lang_token" in dataframe.columns:
            self.langs = dataframe["lang_token"].fillna("<LANG=other>").tolist()
        else:
            self.langs = None

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        code = self.codes[idx]

        # Prepend language token if using shared model
        if self.add_lang_tokens and self.langs:
            lang = self.langs[idx]
            if not lang.startswith("<LANG="):
                lang = LANG_TOKEN_MAP.get(lang, "<LANG=other>")
            code = f"{lang} {code}"

        encoding = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )

        score = self.scores[idx]
        if self.normalize_target:
            score = score / 10.0  # Normalize to [0, 1]

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "severity": torch.tensor(score, dtype=torch.float32),
        }


# ─── DataLoader Factory ─────────────────────────────────────────────────────


def load_severity_splits(tier: str) -> dict:
    """Load train/val/test CSV splits for a tier's severity data.

    Args:
        tier: One of 'tier1_c_cpp', 'tier2_cpp', etc., or 'all_shared'

    Returns:
        dict with 'train', 'val', 'test' DataFrames
    """
    if tier == "all_shared":
        # Combine all tiers for shared model training
        splits = {"train": [], "val": [], "test": []}
        for t, d in TIER_DIRS.items():
            for s in splits:
                path = os.path.join(d, f"{s}.csv")
                if os.path.exists(path):
                    df = pd.read_csv(path)
                    # Ensure language column exists
                    if "language" not in df.columns and "lang_token" in df.columns:
                        df["language"] = df["lang_token"].str.extract(r"<LANG=(\w+)>")[0]
                    elif "language" not in df.columns:
                        # Infer from tier name
                        lang_map = {
                            "tier1_c_cpp": "C",
                            "tier2_cpp": "C++",
                            "tier2_python": "Python",
                            "tier2_php": "PHP",
                        }
                        df["language"] = lang_map.get(t, "Other")
                    splits[s].append(df)

        return {s: pd.concat(dfs, ignore_index=True) for s, dfs in splits.items()}

    else:
        sev_dir = TIER_DIRS.get(tier)
        if not sev_dir or not os.path.isdir(sev_dir):
            raise FileNotFoundError(f"Severity data not found for tier: {tier}")

        result = {}
        for split in ["train", "val", "test"]:
            path = os.path.join(sev_dir, f"{split}.csv")
            if os.path.exists(path):
                result[split] = pd.read_csv(path)
            else:
                raise FileNotFoundError(f"Missing {split}.csv in {sev_dir}")
        return result


def create_severity_dataloaders(
    tier: str,
    model_name: str = "codet5",
    max_length: int = 512,
    batch_size: int = 32,
    add_lang_tokens: bool = False,
    max_samples: int = None,
    normalize_target: bool = True,
) -> tuple:
    """Create train/val/test DataLoaders for severity regression.

    Args:
        tier           : 'tier1_c_cpp', 'tier2_cpp', ..., or 'all_shared'
        model_name     : 'codet5' or 'graphcodebert'
        max_length     : max token length
        batch_size     : batch size
        add_lang_tokens: prepend <LANG=xx> tokens (for shared model)
        max_samples    : subsample training data
        normalize_target: if True, scale CVSS 0-10 to 0-1

    Returns:
        (train_loader, val_loader, test_loader, metadata_dict)
    """
    splits = load_severity_splits(tier)

    # Get tokenizer
    tokenizer = get_tokenizer(model_name)

    # Add language tokens to tokenizer vocab if needed
    if add_lang_tokens:
        new_tokens = list(LANG_TOKEN_MAP.values())
        added = tokenizer.add_tokens(new_tokens)
        if added > 0:
            print(f"  Added {added} language tokens to tokenizer")

    # Subsample if requested
    if max_samples and len(splits["train"]) > max_samples:
        splits["train"] = splits["train"].sample(
            n=max_samples, random_state=42
        ).reset_index(drop=True)
        print(f"  Subsampled training data to {max_samples} samples")

    # Build datasets
    train_ds = SeverityDataset(
        splits["train"], tokenizer, max_length,
        add_lang_tokens=add_lang_tokens,
        normalize_target=normalize_target,
    )
    val_ds = SeverityDataset(
        splits["val"], tokenizer, max_length,
        add_lang_tokens=add_lang_tokens,
        normalize_target=normalize_target,
    )
    test_ds = SeverityDataset(
        splits["test"], tokenizer, max_length,
        add_lang_tokens=add_lang_tokens,
        normalize_target=normalize_target,
    )

    # Metadata
    train_scores = splits["train"]["cvss_score"].values
    meta = {
        "tier": tier,
        "model_name": model_name,
        "train_size": len(train_ds),
        "val_size": len(val_ds),
        "test_size": len(test_ds),
        "score_mean": float(train_scores.mean()),
        "score_std": float(train_scores.std()),
        "score_min": float(train_scores.min()),
        "score_max": float(train_scores.max()),
        "vocab_size": len(tokenizer),
        "normalized": normalize_target,
    }

    print(f"  Severity data loaded: train={meta['train_size']}, "
          f"val={meta['val_size']}, test={meta['test_size']}")
    print(f"  CVSS range: [{meta['score_min']:.1f}, {meta['score_max']:.1f}], "
          f"mean={meta['score_mean']:.2f} ± {meta['score_std']:.2f}")

    # DataLoaders
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              num_workers=0, pin_memory=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False,
                            num_workers=0, pin_memory=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False,
                             num_workers=0, pin_memory=True)

    return train_loader, val_loader, test_loader, meta
