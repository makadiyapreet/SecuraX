"""
dataset_repair.py — Phase 4: Code Repair Dataset & DataLoaders.

Loads fix-pair data (func_before → func_after) for seq2seq code repair training
using CodeT5. Supports per-tier loading and a combined cross-tier shared dataset.

Input format:  "Fix <LANG> CWE-<id> <cwe_description>: <vulnerable_code>"
Target format: "<fixed_code>"

Usage:
    from src.data.dataset_repair import create_repair_dataloaders

    # Per-tier
    train_dl, val_dl, test_dl, meta = create_repair_dataloaders(
        tier="tier1_c_cpp", max_source_length=512, batch_size=16
    )

    # Shared across all tiers (Approach C)
    train_dl, val_dl, test_dl, meta = create_repair_dataloaders(
        tier="all_shared", max_source_length=512, batch_size=16,
        add_lang_tokens=True
    )
"""

import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader

# ─── Project root ────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.data.dataset_multilang import get_tokenizer, MODEL_TOKENIZER_MAP

logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

TIER_DIRS = {
    "tier1_c_cpp": os.path.join(DATA_DIR, "tier1_c_cpp", "repair"),
    "tier2_cpp": os.path.join(DATA_DIR, "tier2_cpp", "repair"),
    "tier2_python": os.path.join(DATA_DIR, "tier2_python", "repair"),
    "tier2_php": os.path.join(DATA_DIR, "tier2_php", "repair"),
    "tier3_shared": os.path.join(DATA_DIR, "tier3_shared", "repair"),
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

# CWE descriptions for common vulnerability types used in the input prompt.
# Maps CWE-ID strings (e.g. "CWE-119") to short human-readable descriptions.
CWE_DESCRIPTIONS: Dict[str, str] = {
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow",
    "CWE-189": "Numeric Errors",
    "CWE-200": "Information Exposure",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-78": "OS Command Injection",
    "CWE-77": "Command Injection",
    "CWE-264": "Permissions and Access Control",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption",
    "CWE-312": "Cleartext Storage",
    "CWE-320": "Key Management Errors",
    "CWE-327": "Broken Crypto Algorithm",
    "CWE-330": "Insufficient Randomness",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-369": "Divide By Zero",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Memory Leak",
    "CWE-415": "Double Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-459": "Incomplete Cleanup",
    "CWE-466": "Return of Pointer to Local Buffer",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE Injection",
    "CWE-617": "Reachable Assertion",
    "CWE-668": "Exposure to Wrong Sphere",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-682": "Incorrect Calculation",
    "CWE-704": "Incorrect Type Conversion",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-762": "Mismatched Memory Routines",
    "CWE-770": "Allocation without Limits",
    "CWE-772": "Missing Resource Release",
    "CWE-835": "Infinite Loop",
    "CWE-843": "Type Confusion",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-NVD-Other": "Other Vulnerability",
    "CWE-Other": "Other Vulnerability",
}


# ─── Dataset ─────────────────────────────────────────────────────────────────


class RepairDataset(Dataset):
    """PyTorch Dataset for seq2seq code repair with CodeT5.

    Each sample returns:
        input_ids       : tokenized source prompt  (int64) [max_source_length]
        attention_mask  : source attention mask      (int64) [max_source_length]
        labels          : tokenized target code      (int64) [max_target_length]

    The source prompt has the format:
        "Fix <LANG> CWE-<id> <cwe_description>: <vulnerable_code>"

    The target is the fixed code (func_after).
    """

    def __init__(
        self,
        dataframe: pd.DataFrame,
        tokenizer,
        max_source_length: int = 512,
        max_target_length: int = 512,
        add_lang_tokens: bool = False,
    ):
        """Initialise the RepairDataset.

        Args:
            dataframe:         DataFrame with func_before, func_after, cwe_id, language columns.
            tokenizer:         HuggingFace tokenizer (CodeT5).
            max_source_length: Maximum token length for the source (input) sequence.
            max_target_length: Maximum token length for the target (output) sequence.
            add_lang_tokens:   If True, prepend <LANG=xx> tokens to the source prompt.
        """
        self.tokenizer = tokenizer
        self.max_source_length = max_source_length
        self.max_target_length = max_target_length
        self.add_lang_tokens = add_lang_tokens

        # Extract columns
        self.func_before: List[str] = dataframe["func_before"].astype(str).tolist()
        self.func_after: List[str] = dataframe["func_after"].astype(str).tolist()
        self.cwe_ids: List[str] = dataframe["cwe_id"].fillna("CWE-Other").astype(str).tolist()

        # Language info
        if "language" in dataframe.columns:
            self.languages: List[str] = dataframe["language"].fillna("Other").astype(str).tolist()
        elif "lang_token" in dataframe.columns:
            # Extract language name from lang_token for display
            self.languages = dataframe["lang_token"].fillna("<LANG=other>").astype(str).tolist()
        else:
            self.languages = ["Other"] * len(dataframe)

    def __len__(self) -> int:
        return len(self.func_before)

    def _build_source_prompt(self, idx: int) -> str:
        """Build the source prompt for a given sample.

        Format: "Fix <LANG> CWE-<id> <cwe_description>: <vulnerable_code>"
        """
        lang = self.languages[idx]
        cwe_id = self.cwe_ids[idx]

        # Resolve language display name
        if lang.startswith("<LANG="):
            # Reverse lookup from token to language name
            lang_display = lang  # fallback to raw token
            for name, token in LANG_TOKEN_MAP.items():
                if token == lang:
                    lang_display = name
                    break
        else:
            lang_display = lang

        # CWE description lookup
        cwe_desc = CWE_DESCRIPTIONS.get(cwe_id, "Vulnerability")

        # Build prompt
        prompt = f"Fix {lang_display} {cwe_id} {cwe_desc}: {self.func_before[idx]}"

        # Optionally prepend language token for shared model
        if self.add_lang_tokens:
            if lang.startswith("<LANG="):
                lang_token = lang
            else:
                lang_token = LANG_TOKEN_MAP.get(lang, "<LANG=other>")
            prompt = f"{lang_token} {prompt}"

        return prompt

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        # Source: task prompt with vulnerable code
        source_text = self._build_source_prompt(idx)

        # Target: fixed code
        target_text = self.func_after[idx]

        # Tokenize source
        source_encoding = self.tokenizer(
            source_text,
            max_length=self.max_source_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        # Tokenize target
        target_encoding = self.tokenizer(
            target_text,
            max_length=self.max_target_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        # Replace padding token ids in labels with -100 so they are ignored by loss
        labels = target_encoding["input_ids"].squeeze(0).clone()
        labels[labels == self.tokenizer.pad_token_id] = -100

        return {
            "input_ids": source_encoding["input_ids"].squeeze(0),
            "attention_mask": source_encoding["attention_mask"].squeeze(0),
            "labels": labels,
        }


# ─── Filtering ───────────────────────────────────────────────────────────────


def filter_valid_repair_pairs(df: pd.DataFrame) -> pd.DataFrame:
    """Filter out invalid fix pairs from the DataFrame.

    Removes rows where:
      - func_after is null, empty, or the literal string "None"
      - func_before is null, empty, or the literal string "None"
      - func_before == func_after (no actual fix)

    Args:
        df: Raw DataFrame with func_before and func_after columns.

    Returns:
        Filtered DataFrame with only valid fix pairs.
    """
    n_before = len(df)

    # Convert to string for safe comparison
    df = df.copy()
    df["func_before"] = df["func_before"].astype(str)
    df["func_after"] = df["func_after"].astype(str)

    # Filter out invalid func_after
    mask_after = (
        df["func_after"].notna()
        & (df["func_after"] != "")
        & (df["func_after"] != "None")
        & (df["func_after"] != "nan")
    )

    # Filter out invalid func_before
    mask_before = (
        df["func_before"].notna()
        & (df["func_before"] != "")
        & (df["func_before"] != "None")
        & (df["func_before"] != "nan")
    )

    # Filter out identical pairs (no actual fix)
    mask_different = df["func_before"].str.strip() != df["func_after"].str.strip()

    df = df[mask_before & mask_after & mask_different].reset_index(drop=True)

    n_after = len(df)
    n_removed = n_before - n_after

    if n_removed > 0:
        logger.info(
            f"  Filtered repair pairs: {n_before:,} → {n_after:,} "
            f"(removed {n_removed:,} invalid)"
        )

    return df


# ─── Loading ─────────────────────────────────────────────────────────────────


def load_repair_splits(tier: str) -> Dict[str, pd.DataFrame]:
    """Load train/val/test CSV splits for a tier's repair data.

    Filters out invalid fix pairs automatically.

    Args:
        tier: One of 'tier1_c_cpp', 'tier2_cpp', etc., or 'all_shared'.

    Returns:
        dict with 'train', 'val', 'test' DataFrames (filtered).
    """
    if tier == "all_shared":
        # Combine all tiers for shared model training
        splits: Dict[str, List[pd.DataFrame]] = {"train": [], "val": [], "test": []}

        for t, d in TIER_DIRS.items():
            for s in splits:
                path = os.path.join(d, f"{s}.csv")
                if os.path.exists(path):
                    df = pd.read_csv(path, low_memory=False)

                    # Ensure language column exists
                    if "language" not in df.columns and "lang_token" in df.columns:
                        df["language"] = (
                            df["lang_token"]
                            .str.extract(r"<LANG=(\w+)>")[0]
                        )
                    elif "language" not in df.columns:
                        # Infer from tier name
                        lang_map = {
                            "tier1_c_cpp": "C",
                            "tier2_cpp": "C++",
                            "tier2_python": "Python",
                            "tier2_php": "PHP",
                        }
                        df["language"] = lang_map.get(t, "Other")

                    df["_source_tier"] = t
                    splits[s].append(df)
                else:
                    logger.warning(f"  Missing {s}.csv for tier {t} — skipping")

        result = {}
        for s, dfs in splits.items():
            if dfs:
                combined = pd.concat(dfs, ignore_index=True)
                result[s] = filter_valid_repair_pairs(combined)
            else:
                raise FileNotFoundError(
                    f"No repair data found for split '{s}' in any tier"
                )

        return result

    else:
        repair_dir = TIER_DIRS.get(tier)
        if not repair_dir or not os.path.isdir(repair_dir):
            raise FileNotFoundError(
                f"Repair data not found for tier: {tier}\n"
                f"Expected directory: {repair_dir}"
            )

        result = {}
        for split in ["train", "val", "test"]:
            path = os.path.join(repair_dir, f"{split}.csv")
            if os.path.exists(path):
                df = pd.read_csv(path, low_memory=False)
                result[split] = filter_valid_repair_pairs(df)
            else:
                raise FileNotFoundError(f"Missing {split}.csv in {repair_dir}")

        return result


# ─── DataLoader Factory ─────────────────────────────────────────────────────


def create_repair_dataloaders(
    tier: str,
    model_name: str = "codet5",
    max_source_length: int = 512,
    max_target_length: int = 512,
    batch_size: int = 16,
    num_workers: int = 0,
    add_lang_tokens: bool = False,
    max_samples: Optional[int] = None,
) -> Tuple[DataLoader, DataLoader, DataLoader, Dict[str, Any]]:
    """Create train/val/test DataLoaders for code repair (seq2seq).

    Args:
        tier              : 'tier1_c_cpp', 'tier2_cpp', ..., or 'all_shared'
        model_name        : 'codet5' (default; other models not recommended for seq2seq)
        max_source_length : max token length for source (input) sequences
        max_target_length : max token length for target (output) sequences
        batch_size        : batch size
        num_workers       : dataloader workers
        add_lang_tokens   : prepend <LANG=xx> tokens (for shared model)
        max_samples       : subsample training data (useful for debugging)

    Returns:
        (train_loader, val_loader, test_loader, metadata_dict)
    """
    use_lang_tokens = "tier3" in tier or tier == "all_shared" or add_lang_tokens

    print(f"\n{'=' * 60}")
    print(
        f"  Loading repair data: tier={tier}, model={model_name}"
    )
    print(
        f"  Max source: {max_source_length}, Max target: {max_target_length}, "
        f"Batch size: {batch_size}"
    )
    print(f"  Lang tokens: {use_lang_tokens}")
    print(f"{'=' * 60}\n")

    # ─────────────────────────────────────────────
    # Load tokenizer — use AutoTokenizer directly for CodeT5 seq2seq
    # (bypass get_tokenizer which uses RobertaTokenizer, incompatible
    #  with Python 3.13 tokenizers library)
    # ─────────────────────────────────────────────

    from transformers import AutoTokenizer

    codet5_name = "Salesforce/codet5-base"
    local_path = os.path.join(
        PROJECT_ROOT, "models", "pretrained", "codet5-base"
    )
    if os.path.isdir(local_path):
        tokenizer = AutoTokenizer.from_pretrained(local_path)
    else:
        tokenizer = AutoTokenizer.from_pretrained(codet5_name)

    # Add language tokens to tokenizer vocab if needed
    if use_lang_tokens:
        new_tokens = list(LANG_TOKEN_MAP.values())
        added = tokenizer.add_tokens(new_tokens)
        if added > 0:
            print(f"  Added {added} language tokens to tokenizer")

    # ─────────────────────────────────────────────
    # Load & filter splits
    # ─────────────────────────────────────────────

    splits = load_repair_splits(tier)

    # ─────────────────────────────────────────────
    # Subsample training data if requested
    # ─────────────────────────────────────────────

    if max_samples and len(splits["train"]) > max_samples:
        splits["train"] = (
            splits["train"]
            .sample(n=max_samples, random_state=42)
            .reset_index(drop=True)
        )
        print(f"  ⚡ Subsampled training data to {max_samples:,} samples")

    # ─────────────────────────────────────────────
    # Print dataset sizes
    # ─────────────────────────────────────────────

    for name, df in [("Train", splits["train"]),
                     ("Val", splits["val"]),
                     ("Test", splits["test"])]:
        print(f"  {name:>5}: {len(df):>8,} valid fix pairs")

        # Show language distribution
        if "language" in df.columns:
            lang_counts = df["language"].value_counts()
            top_langs = lang_counts.head(5)
            lang_str = ", ".join(
                f"{lang}: {cnt:,}" for lang, cnt in top_langs.items()
            )
            print(f"         Languages: {lang_str}")

    # ─────────────────────────────────────────────
    # Build datasets
    # ─────────────────────────────────────────────

    train_ds = RepairDataset(
        splits["train"], tokenizer, max_source_length, max_target_length,
        add_lang_tokens=use_lang_tokens,
    )
    val_ds = RepairDataset(
        splits["val"], tokenizer, max_source_length, max_target_length,
        add_lang_tokens=use_lang_tokens,
    )
    test_ds = RepairDataset(
        splits["test"], tokenizer, max_source_length, max_target_length,
        add_lang_tokens=use_lang_tokens,
    )

    # ─────────────────────────────────────────────
    # Metadata
    # ─────────────────────────────────────────────

    # CWE distribution in training set
    cwe_counts = splits["train"]["cwe_id"].fillna("CWE-Other").value_counts()
    top_cwes = {str(k): int(v) for k, v in cwe_counts.head(10).items()}

    # Language distribution in training set
    if "language" in splits["train"].columns:
        lang_counts = splits["train"]["language"].value_counts()
        lang_dist = {str(k): int(v) for k, v in lang_counts.items()}
    else:
        lang_dist = {}

    meta: Dict[str, Any] = {
        "tier": tier,
        "task": "repair",
        "model_name": model_name,
        "max_source_length": max_source_length,
        "max_target_length": max_target_length,
        "train_size": len(train_ds),
        "val_size": len(val_ds),
        "test_size": len(test_ds),
        "use_lang_tokens": use_lang_tokens,
        "vocab_size": len(tokenizer),
        "top_cwes": top_cwes,
        "language_distribution": lang_dist,
    }

    # ─────────────────────────────────────────────
    # DataLoaders
    # ─────────────────────────────────────────────

    pin_memory = torch.cuda.is_available()

    train_loader = DataLoader(
        train_ds, batch_size=batch_size, shuffle=True,
        num_workers=num_workers, pin_memory=pin_memory, drop_last=False,
    )
    val_loader = DataLoader(
        val_ds, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=pin_memory,
    )
    test_loader = DataLoader(
        test_ds, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=pin_memory,
    )

    print(f"\n  ✅ Repair DataLoaders ready")
    print(f"     Train: {len(train_loader):>6} batches")
    print(f"     Val:   {len(val_loader):>6} batches")
    print(f"     Test:  {len(test_loader):>6} batches")

    return train_loader, val_loader, test_loader, meta


# ─── Statistics ──────────────────────────────────────────────────────────────


def get_repair_statistics() -> Dict[str, Any]:
    """Compute statistics for all repair tiers.

    Returns a dict with per-tier and per-language counts of valid fix pairs
    across train/val/test splits.

    Returns:
        Dictionary with structure:
        {
            "per_tier": {
                "tier1_c_cpp": {"train": N, "val": N, "test": N, "total": N},
                ...
            },
            "per_language": {
                "C": N, "C++": N, ...
            },
            "grand_total": N,
        }
    """
    stats: Dict[str, Any] = {
        "per_tier": {},
        "per_language": {},
        "grand_total": 0,
    }

    all_lang_counts: Dict[str, int] = {}

    for tier_name, tier_dir in TIER_DIRS.items():
        tier_stats: Dict[str, int] = {}
        tier_total = 0

        for split in ["train", "val", "test"]:
            path = os.path.join(tier_dir, f"{split}.csv")
            if os.path.exists(path):
                df = pd.read_csv(path, low_memory=False)
                df = filter_valid_repair_pairs(df)
                tier_stats[split] = len(df)
                tier_total += len(df)

                # Accumulate language counts
                if "language" in df.columns:
                    for lang, cnt in df["language"].value_counts().items():
                        all_lang_counts[str(lang)] = (
                            all_lang_counts.get(str(lang), 0) + cnt
                        )
            else:
                tier_stats[split] = 0

        tier_stats["total"] = tier_total
        stats["per_tier"][tier_name] = tier_stats
        stats["grand_total"] += tier_total

    stats["per_language"] = dict(
        sorted(all_lang_counts.items(), key=lambda x: x[1], reverse=True)
    )

    return stats


# ─── CLI ─────────────────────────────────────────────────────────────────────


if __name__ == "__main__":

    import argparse
    import json

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Test Phase 4 repair data pipeline."
    )

    parser.add_argument(
        "--tier",
        type=str,
        default=None,
        help=(
            "Tier key (e.g. tier1_c_cpp, tier2_python, all_shared). "
            "If omitted, prints statistics for all tiers."
        ),
    )

    parser.add_argument(
        "--model",
        type=str,
        default="codet5",
        choices=list(MODEL_TOKENIZER_MAP.keys()),
    )

    parser.add_argument(
        "--max-source-length",
        type=int,
        default=512,
    )

    parser.add_argument(
        "--max-target-length",
        type=int,
        default=512,
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
    )

    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Print statistics and exit without loading tokenizer/data.",
    )

    args = parser.parse_args()

    # ─────────────────────────────────────────────
    # Statistics mode
    # ─────────────────────────────────────────────

    if args.stats_only or args.tier is None:
        print("\n" + "=" * 60)
        print("  Phase 4 Repair Data Statistics")
        print("=" * 60)

        stats = get_repair_statistics()

        print(f"\n  {'Tier':<20} {'Train':>8} {'Val':>8} {'Test':>8} {'Total':>8}")
        print(f"  {'-' * 52}")

        for tier_name, tier_info in stats["per_tier"].items():
            print(
                f"  {tier_name:<20} "
                f"{tier_info.get('train', 0):>8,} "
                f"{tier_info.get('val', 0):>8,} "
                f"{tier_info.get('test', 0):>8,} "
                f"{tier_info.get('total', 0):>8,}"
            )

        print(f"  {'-' * 52}")
        print(f"  {'Grand Total':<20} {'':>8} {'':>8} {'':>8} {stats['grand_total']:>8,}")

        if stats["per_language"]:
            print(f"\n  Language Distribution (all tiers):")
            for lang, cnt in stats["per_language"].items():
                print(f"    {lang:<20} {cnt:>8,}")

        print()
        sys.exit(0)

    # ─────────────────────────────────────────────
    # DataLoader smoke test
    # ─────────────────────────────────────────────

    train_dl, val_dl, test_dl, meta = create_repair_dataloaders(
        tier=args.tier,
        model_name=args.model,
        max_source_length=args.max_source_length,
        max_target_length=args.max_target_length,
        batch_size=args.batch_size,
    )

    print("\n  Metadata:")
    print(json.dumps(meta, indent=4, default=str))

    # Smoke test: grab first batch
    print("\n  Smoke test — first training batch:")
    batch = next(iter(train_dl))

    for k, v in batch.items():
        print(f"    {k}: shape={v.shape}, dtype={v.dtype}")

    # Decode a sample to verify prompt format
    tokenizer = get_tokenizer(args.model)
    sample_input = tokenizer.decode(
        batch["input_ids"][0], skip_special_tokens=True
    )
    sample_labels = batch["labels"][0]
    sample_labels[sample_labels == -100] = tokenizer.pad_token_id
    sample_target = tokenizer.decode(sample_labels, skip_special_tokens=True)

    print(f"\n  Sample input  (truncated): {sample_input[:200]}...")
    print(f"  Sample target (truncated): {sample_target[:200]}...")

    print("\n  ✅ Phase 4 repair data pipeline smoke test passed.")

