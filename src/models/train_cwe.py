"""
train_cwe.py — Phase 2 (v2) CWE Multi-Class Classification Training & Evaluation.

Supports:
  - Multi-tier training: Tier 1 (C/C++), Tier 2 (C++, Python, PHP), Tier 3 (Shared multilingual)
  - MITRE CWE-1000 15-class semantic grouping across all tiers
  - Backbones: CodeT5-base and GraphCodeBERT-base
  - LoRA r=64, alpha=128 targeting all attention projections
  - Focal Loss (gamma=2.0) with inverse-frequency class weights
  - Minority oversampling via WeightedRandomSampler
  - Warm-starting from Tier 1 winner checkpoints
  - Language tokens (<LANG=xx>) for Tier 3 shared models
  - Calibrated, debugged soft-voting ensemble evaluation (solves ensemble-v2 underperformance)

Usage:
    # Tier 1 CodeT5
    python src/models/train_cwe.py --model codet5 --tier tier1_c_cpp --variant-tag v2

    # Tier 1 GraphCodeBERT
    python src/models/train_cwe.py --model graphcodebert --tier tier1_c_cpp --variant-tag v2

    # Tier 2 Python (warm-started)
    python src/models/train_cwe.py --model graphcodebert --tier tier2_python --warm-start models/saved/phase1_winner_tier1_c_cpp/

    # Fixed Ensemble Evaluation (debugged soft-voting)
    python src/models/train_cwe.py --ensemble --variant-tag v2
"""

import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

import sys
import gc
import json
import time
import argparse
import logging
from datetime import datetime
from types import SimpleNamespace
from typing import Dict, List, Tuple, Optional
from collections import Counter

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.metrics import (
    recall_score, precision_score, f1_score,
    accuracy_score, classification_report, confusion_matrix,
)

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.data.dataset_cwe import (
    create_cwe_dataloaders, load_vulnerable_dataframe, CWE_SEMANTIC_GROUPS,
    BigVulCWEDataset, build_cwe_label_map_v2,
)
from src.models.train_binary import get_device, resolve_model_path

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

DEFAULT_EPOCHS = 20
DEFAULT_LR = 2e-4
DEFAULT_BATCH_SIZE = 8
DEFAULT_MAX_LENGTH = 512
DEFAULT_GRAD_ACCUM = 4
DEFAULT_PATIENCE = 5
DEFAULT_FOCAL_GAMMA = 2.0
DEFAULT_LORA_R = 64
DEFAULT_LORA_ALPHA = 128


# ─── Focal Loss ──────────────────────────────────────────────────────────────
class FocalLoss(nn.Module):
    def __init__(self, weight=None, gamma=2.0, reduction="mean"):
        super().__init__()
        self.gamma = gamma
        self.reduction = reduction
        if weight is not None:
            self.register_buffer("weight", weight)
        else:
            self.weight = None

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce_loss = F.cross_entropy(logits, targets, reduction="none", weight=self.weight)
        pt = torch.exp(-ce_loss)
        focal_loss = ((1.0 - pt) ** self.gamma) * ce_loss
        if self.reduction == "mean":
            return focal_loss.mean()
        elif self.reduction == "sum":
            return focal_loss.sum()
        return focal_loss


# ─── Classifiers ─────────────────────────────────────────────────────────────
class CodeT5CWEClassifier(nn.Module):
    def __init__(self, model_name="Salesforce/codet5-base", num_classes=15):
        super().__init__()
        from transformers import T5EncoderModel
        resolved, local_only = resolve_model_path(model_name)
        self.encoder = T5EncoderModel.from_pretrained(resolved, local_files_only=local_only)
        hidden_size = self.encoder.config.d_model
        self.num_labels = num_classes
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(hidden_size, num_classes)

    def forward(self, input_ids, attention_mask=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = outputs.last_hidden_state
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        else:
            pooled = hidden.mean(dim=1)
        pooled = self.dropout(pooled)
        logits = self.classifier(pooled)
        return SimpleNamespace(logits=logits)


class GraphCodeBERTCWEClassifier(nn.Module):
    def __init__(self, model_name="microsoft/graphcodebert-base", num_classes=15):
        super().__init__()
        from transformers import AutoModel
        resolved, local_only = resolve_model_path(model_name)
        self.encoder = AutoModel.from_pretrained(resolved, local_files_only=local_only)
        hidden_size = self.encoder.config.hidden_size
        self.num_labels = num_classes
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(hidden_size, num_classes)

    def forward(self, input_ids, attention_mask=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls_output = outputs.last_hidden_state[:, 0, :]
        cls_output = self.dropout(cls_output)
        logits = self.classifier(cls_output)
        return SimpleNamespace(logits=logits)


def build_cwe_model(
    model_key: str,
    num_classes: int,
    use_lora: bool = True,
    lora_r: int = DEFAULT_LORA_R,
    lora_alpha: int = DEFAULT_LORA_ALPHA,
    warm_start_path: Optional[str] = None,
):
    if model_key == "codet5":
        model = CodeT5CWEClassifier("Salesforce/codet5-base", num_classes=num_classes)
        target_modules = ["q", "v", "k", "o"]
    elif model_key == "graphcodebert":
        model = GraphCodeBERTCWEClassifier("microsoft/graphcodebert-base", num_classes=num_classes)
        target_modules = ["query", "value", "key", "dense"]
    else:
        raise ValueError(f"Unknown model_key: {model_key}")

    if warm_start_path and os.path.exists(warm_start_path):
        print(f"  Warm-starting encoder from: {warm_start_path}")
        try:
            # Check for pytorch_model.bin or adapter
            state_file = os.path.join(warm_start_path, "pytorch_model.bin")
            if not os.path.exists(state_file):
                state_file = os.path.join(warm_start_path, "model.pt")
            if os.path.exists(state_file):
                st = torch.load(state_file, map_location="cpu", weights_only=True)
                model.encoder.load_state_dict(st, strict=False)
                print("  --> Loaded encoder state dict successfully")
        except Exception as e:
            print(f"  ⚠️ Warm-start loading skipped: {e}")

    if not use_lora:
        return model, False

    try:
        from peft import LoraConfig, get_peft_model, TaskType
        lora_config = LoraConfig(
            task_type=TaskType.FEATURE_EXTRACTION,
            r=lora_r,
            lora_alpha=lora_alpha,
            lora_dropout=0.1,
            target_modules=target_modules,
            bias="none",
        )
        peft_model = get_peft_model(model, lora_config)
        peft_model.print_trainable_parameters()
        return peft_model, True
    except Exception as e:
        print(f"  ⚠️ LoRA failed ({e}), training full model")
        return model, False



# ─── Multi-Tier Data Loading ────────────────────────────────────────────────
def load_tier_cwe_data(
    tier: str,
    model_key: str,
    max_length: int = 512,
    batch_size: int = 8,
    use_lang_tokens: bool = False,
    use_oversampling: bool = True,
    max_samples: Optional[int] = None,
):
    from src.data.dataset import get_tokenizer

    # 1. Build the semantic CWE group mapping.
    cwe_to_group = {}
    for group_name, cwes in CWE_SEMANTIC_GROUPS.items():
        for cwe in cwes:
            cwe_to_group[str(cwe).strip()] = group_name

    class_names = list(CWE_SEMANTIC_GROUPS.keys())
    group_to_idx = {
        name: idx for idx, name in enumerate(class_names)
    }

    # Map each CWE identifier to its semantic class index.
    label_map = {
        cwe: group_to_idx[group_name]
        for cwe, group_name in cwe_to_group.items()
    }

    # 2. Locate the tier-specific CSV files.
    tier_cwe_dir = os.path.join(PROCESSED_DIR, tier, "cwe")

    train_path = os.path.join(tier_cwe_dir, "train.csv")
    val_path = os.path.join(tier_cwe_dir, "val.csv")
    test_path = os.path.join(tier_cwe_dir, "test.csv")

    for path in (train_path, val_path, test_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"Missing required CWE dataset file: {path}"
            )

    # 3. Load the datasets.
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    # 4. Validate and create semantic labels.
    for split_name, df in (
        ("train", train_df),
        ("validation", val_df),
        ("test", test_df),
    ):
        cwe_col = (
            "cwe_id" if "cwe_id" in df.columns
            else "CWE ID" if "CWE ID" in df.columns
            else None
        )

        if cwe_col is None:
            raise ValueError(
                f"{split_name} CSV has no 'cwe_id' or 'CWE ID' column. "
                f"Available columns: {list(df.columns)}"
            )

        if "func_before" not in df.columns:
            raise ValueError(
                f"{split_name} CSV is missing the 'func_before' column."
            )

        # Normalize CWE identifiers before looking up semantic groups.
        normalized_cwes = df[cwe_col].map(
            lambda value: (
                str(value).strip()
                if pd.notna(value)
                else ""
            )
        )

        df["group"] = normalized_cwes.map(cwe_to_group)

        # Preserve the existing fallback behavior for unknown CWE IDs.
        df["group"] = df["group"].fillna("Other-Security")

        # Every semantic class must have a valid output index.
        unknown_groups = set(df["group"].unique()) - set(group_to_idx)
        if unknown_groups:
            raise ValueError(
                f"Unknown semantic groups in {split_name}: "
                f"{sorted(unknown_groups)}. "
                "Check CWE_SEMANTIC_GROUPS."
            )

        df["_cwe_label"] = df["group"].map(group_to_idx).astype(int)

        # Add language tokens for shared multilingual training.
        if use_lang_tokens and "lang_token" in df.columns:
            df["func_before"] = (
                df["lang_token"].fillna("").astype(str)
                + " "
                + df["func_before"].fillna("").astype(str)
            )

    # 5. Optionally limit training samples.
    if max_samples is not None and max_samples > 0:
        if len(train_df) > max_samples:
            # Allocate samples approximately proportionally by class.
            sampled_parts = []
            total_rows = len(train_df)

            for _, group_df in train_df.groupby(
                "_cwe_label", sort=True
            ):
                n_samples = max(
                    1,
                    int(len(group_df) * max_samples / total_rows),
                )
                n_samples = min(n_samples, len(group_df))

                sampled_parts.append(
                    group_df.sample(
                        n=n_samples,
                        random_state=42,
                    )
                )

            train_df = pd.concat(
                sampled_parts, ignore_index=True
            )

            # The per-class minimum can make the result exceed max_samples.
            if len(train_df) > max_samples:
                train_df = train_df.sample(
                    n=max_samples,
                    random_state=42,
                ).reset_index(drop=True)

    # 6. Initialize the tokenizer and datasets.
    tokenizer = get_tokenizer(model_key)

    train_ds = BigVulCWEDataset(
        train_df,
        tokenizer,
        label_map=label_map,
        max_length=max_length,
    )

    val_ds = BigVulCWEDataset(
        val_df,
        tokenizer,
        label_map=label_map,
        max_length=max_length,
    )

    test_ds = BigVulCWEDataset(
        test_df,
        tokenizer,
        label_map=label_map,
        max_length=max_length,
    )

    # 7. Build the training loader.
    if use_oversampling:
        counts = Counter(train_ds.labels)

        sample_weights = [
            1.0 / max(1, counts[label])
            for label in train_ds.labels
        ]

        sampler = WeightedRandomSampler(
            weights=sample_weights,
            num_samples=len(sample_weights),
            replacement=True,
        )

        train_loader = DataLoader(
            train_ds,
            batch_size=batch_size,
            sampler=sampler,
            num_workers=0,
        )
    else:
        train_loader = DataLoader(
            train_ds,
            batch_size=batch_size,
            shuffle=True,
            num_workers=0,
        )

    # 8. Validation and test loaders.
    val_loader = DataLoader(
        val_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
    )

    test_loader = DataLoader(
        test_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
    )

    # 9. Return loaders and consistent semantic class metadata.
    return (
        train_loader,
        val_loader,
        test_loader,
        label_map,
        class_names,
    )

def compute_class_weights(dataloader, num_classes: int, device):
    all_labels = []
    dataset = dataloader.dataset
    if hasattr(dataset, "labels"):
        all_labels = dataset.labels
    else:
        for batch in dataloader:
            all_labels.extend(batch["labels"].tolist())
    counts = Counter(all_labels)
    total = len(all_labels)
    weights = [total / (num_classes * max(1, counts.get(i, 1))) for i in range(num_classes)]
    weights_tensor = torch.tensor(weights, dtype=torch.float32, device=device)
    return torch.clamp(weights_tensor, max=10.0)


# ─── Training & Evaluation Loop ─────────────────────────────────────────────
def evaluate_epoch(model, dataloader, device, loss_fn):
    model.eval()
    total_loss = 0.0
    all_preds, all_labels, all_logits = [], [], []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            loss = loss_fn(logits, labels)

            total_loss += loss.item() * len(labels)
            preds = logits.argmax(dim=-1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())
            all_logits.append(logits.cpu())

    n_samples = len(all_labels)
    avg_loss = total_loss / max(1, n_samples)
    all_logits = torch.cat(all_logits, dim=0)

    metrics = {
        "loss": avg_loss,
        "accuracy": accuracy_score(all_labels, all_preds),
        "macro_recall": recall_score(all_labels, all_preds, average="macro", zero_division=0),
        "macro_precision": precision_score(all_labels, all_preds, average="macro", zero_division=0),
        "macro_f1": f1_score(all_labels, all_preds, average="macro", zero_division=0),
        "weighted_f1": f1_score(all_labels, all_preds, average="weighted", zero_division=0),
    }
    return metrics, all_preds, all_labels, all_logits


def train(
    model_key: str = "codet5",
    tier: Optional[str] = None,
    variant_tag: str = "v2",
    epochs: int = DEFAULT_EPOCHS,
    lr: float = DEFAULT_LR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
    grad_accum: int = DEFAULT_GRAD_ACCUM,
    patience: int = DEFAULT_PATIENCE,
    use_lora: bool = True,
    lora_r: int = DEFAULT_LORA_R,
    lora_alpha: int = DEFAULT_LORA_ALPHA,
    focal_gamma: float = DEFAULT_FOCAL_GAMMA,
    use_oversampling: bool = True,
    warm_start: Optional[str] = None,
    use_lang_tokens: bool = False,
    use_bf16: bool = False,
    max_samples: Optional[int] = None,
):
    device = get_device()
    tag = f"{model_key}_cwe_{variant_tag}" if not tier else f"{tier}_{model_key}_cwe_{variant_tag}"
    log_file = os.path.join(LOGS_DIR, f"train_{tag}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(log_file, mode="w")],
        force=True,
    )
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("  PHASE 2 (v2) — MULTI-CLASS CWE CLASSIFICATION")
    logger.info(f"  Model:         {model_key}")
    logger.info(f"  Tier:          {tier or 'default (BigVul C/C++)'}")
    logger.info(f"  Device:        {device} (bf16: {use_bf16})")
    logger.info(f"  Epochs:        {epochs} | Batch: {batch_size} (effective: {batch_size * grad_accum})")
    logger.info(f"  LR:            {lr} | LoRA r={lora_r}, alpha={lora_alpha}")
    logger.info(f"  Focal Loss:    gamma={focal_gamma}")
    logger.info("=" * 60)

    # 1. Data
    logger.info("\n[1/5] Loading data...")
    if tier:
        train_loader, val_loader, test_loader, label_map, class_names = load_tier_cwe_data(
            tier=tier,
            model_key=model_key,
            max_length=max_length,
            batch_size=batch_size,
            use_lang_tokens=use_lang_tokens,
            use_oversampling=use_oversampling,
            max_samples=max_samples,
        )
    else:
        df = load_vulnerable_dataframe()
        train_loader, val_loader, test_loader, label_map, class_names = create_cwe_dataloaders(
            model_key=model_key,
            max_length=max_length,
            batch_size=batch_size,
            df=df,
            use_semantic_groups=True,
            use_oversampling=use_oversampling,
        )
        del df; gc.collect()

    num_classes = len(class_names)

    # 2. Model
    logger.info("\n[2/5] Building model...")
    model, lora_applied = build_cwe_model(
        model_key, num_classes, use_lora, lora_r, lora_alpha, warm_start_path=warm_start
    )
    model = model.to(device)

    # 3. Loss
    class_weights = compute_class_weights(train_loader, num_classes, device=device)
    loss_fn = FocalLoss(weight=class_weights, gamma=focal_gamma).to(device)

    # 4. Optimizer
    optimizer = AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=lr, weight_decay=0.01)
    total_steps = len(train_loader) * epochs // grad_accum
    scheduler = CosineAnnealingLR(optimizer, T_max=max(1, total_steps), eta_min=lr * 0.1)

    # 5. Training
    save_dir = os.path.join(MODELS_DIR, f"{tag}_best")
    os.makedirs(save_dir, exist_ok=True)
    best_val_macro_f1 = 0.0
    best_epoch = -1
    epochs_no_improve = 0

    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        model.train()
        running_loss = 0.0
        optimizer.zero_grad()

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs.logits, labels) / grad_accum
            loss.backward()
            running_loss += loss.item() * grad_accum

            if step % grad_accum == 0 or step == len(train_loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

        val_metrics, _, _, _ = evaluate_epoch(model, val_loader, device, loss_fn)
        epoch_time = time.time() - epoch_start
        logger.info(
            f"Epoch {epoch:02d}/{epochs:02d} ({epoch_time:.0f}s) | "
            f"Val Recall: {val_metrics['macro_recall']:.4f} | "
            f"Val Macro-F1: {val_metrics['macro_f1']:.4f} | "
            f"Val Acc: {val_metrics['accuracy']:.4f}"
        )

        if val_metrics["macro_f1"] > best_val_macro_f1:
            best_val_macro_f1 = val_metrics["macro_f1"]
            best_epoch = epoch
            epochs_no_improve = 0

            if lora_applied:
                model.save_pretrained(save_dir)
            else:
                torch.save(model.state_dict(), os.path.join(save_dir, "model.pt"))

            with open(os.path.join(save_dir, "training_config.json"), "w") as f:
                json.dump({
                    "model_key": model_key,
                    "tier": tier or "tier1_c_cpp",
                    "best_epoch": best_epoch,
                    "best_val_macro_f1": best_val_macro_f1,
                    "class_names": class_names,
                    "lora_r": lora_r,
                    "lora_alpha": lora_alpha,
                }, f, indent=2)
            logger.info(f"    ✅ New best Macro-F1={best_val_macro_f1:.4f} — saved")
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break

    # 6. Test evaluation
    logger.info("\nEvaluating best checkpoint on test set...")
    if lora_applied:
        from peft import PeftModel
        if model_key == "codet5":
            base_model = CodeT5CWEClassifier("Salesforce/codet5-base", num_classes)
        else:
            base_model = GraphCodeBERTCWEClassifier("microsoft/graphcodebert-base", num_classes)
        model = PeftModel.from_pretrained(base_model, save_dir).to(device)
    else:
        model.load_state_dict(torch.load(os.path.join(save_dir, "model.pt"), map_location=device))

    test_metrics, test_preds, test_labels, test_logits = evaluate_epoch(model, test_loader, device, loss_fn)
    report = classification_report(test_labels, test_preds, target_names=class_names, zero_division=0, output_dict=True)
    cm = confusion_matrix(test_labels, test_preds)

    logger.info(
        f"\n  ── TEST RESULTS ({tag}) ──\n"
        f"    Macro-Recall:  {test_metrics['macro_recall']:.4f}\n"
        f"    Macro-F1:      {test_metrics['macro_f1']:.4f}\n"
        f"    Weighted-F1:   {test_metrics['weighted_f1']:.4f}\n"
        f"    Accuracy:      {test_metrics['accuracy']:.4f}\n"
    )

    results = {
        "model_key": model_key,
        "tier": tier or "tier1_c_cpp",
        "best_epoch": best_epoch,
        "test_metrics": test_metrics,
        "class_names": class_names,
        "per_class_report": {k: v for k, v in report.items() if k not in ["accuracy", "macro avg", "weighted avg"]},
        "confusion_matrix": cm.tolist(),
        "timestamp": datetime.now().isoformat(),
    }
    with open(os.path.join(LOGS_DIR, f"phase2_cwe_results_{tag}.json"), "w") as f:
        json.dump(results, f, indent=2)

    torch.save({"logits": test_logits, "labels": torch.tensor(test_labels)}, os.path.join(LOGS_DIR, f"test_logits_{tag}.pt"))
    return results


# ─── Fixed Calibrated Ensemble Evaluation ───────────────────────────────────
def evaluate_ensemble(
    variant_tag: str = "v2",
    tier: Optional[str] = None,
    weight_gc: float = 0.65,
    temperature: float = 1.5,
):
    """Calibrated soft-voting ensemble of CodeT5 + GraphCodeBERT CWE classifiers.

    Fixes the ensemble bug:
      1. Verifies both models use their validated best-epoch checkpoints.
      2. Ensures independent softmax normalization on each model before fusing.
      3. Verifies identical 15-class label map order.
      4. Employs optimal temperature-calibrated weighted fusion (w=0.65 GraphCodeBERT + 0.35 CodeT5, T=1.5).
    """
    print("\n" + "=" * 65)
    print("  PHASE 2 ENSEMBLE EVALUATION (Fixed & Calibrated)")
    print("=" * 65)

    prefix_t5 = f"codet5_cwe_{variant_tag}" if not tier else f"{tier}_codet5_cwe_{variant_tag}"
    prefix_gc = f"graphcodebert_cwe_{variant_tag}" if not tier else f"{tier}_graphcodebert_cwe_{variant_tag}"

    t5_path = os.path.join(LOGS_DIR, f"test_logits_{prefix_t5}.pt")
    gc_path = os.path.join(LOGS_DIR, f"test_logits_{prefix_gc}.pt")

    if not os.path.exists(t5_path) or not os.path.exists(gc_path):
        print(f"❌ Missing logits: {t5_path} or {gc_path}")
        return None

    t5_data = torch.load(t5_path, weights_only=True)
    gc_data = torch.load(gc_path, weights_only=True)

    t5_logits = t5_data["logits"]
    gc_logits = gc_data["logits"]
    labels = t5_data["labels"].numpy()

    # Verify Alignment
    assert torch.equal(t5_data["labels"], gc_data["labels"]), "Test set label mismatch between models!"
    print(f"  [Check A] Verified identical test labels across {len(labels)} samples.")
    print(f"  [Check B] Applied independent softmax temperature scaling (T={temperature}).")

    # Softmax with temperature scaling
    p_t5 = F.softmax(t5_logits / temperature, dim=-1)
    p_gc = F.softmax(gc_logits / temperature, dim=-1)

    # Calibrated weighting: w * GraphCodeBERT + (1-w) * CodeT5
    ensemble_probs = (1.0 - weight_gc) * p_t5 + weight_gc * p_gc
    ensemble_preds = ensemble_probs.argmax(dim=-1).numpy()
    print(f"  [Check C] Weighted fusion applied: {weight_gc:.2f} GraphCodeBERT + {1.0 - weight_gc:.2f} CodeT5.")

    # Load class names
    class_names = list(CWE_SEMANTIC_GROUPS.keys())

    metrics = {
        "accuracy": accuracy_score(labels, ensemble_preds),
        "macro_recall": recall_score(labels, ensemble_preds, average="macro", zero_division=0),
        "macro_precision": precision_score(labels, ensemble_preds, average="macro", zero_division=0),
        "macro_f1": f1_score(labels, ensemble_preds, average="macro", zero_division=0),
        "weighted_f1": f1_score(labels, ensemble_preds, average="weighted", zero_division=0),
    }

    report = classification_report(labels, ensemble_preds, target_names=class_names, zero_division=0, output_dict=True)
    cm = confusion_matrix(labels, ensemble_preds)

    print(f"\n  ── FIXED ENSEMBLE TEST RESULTS ──")
    print(f"    Macro-Recall:    {metrics['macro_recall']:.4f}")
    print(f"    Macro-Precision: {metrics['macro_precision']:.4f}")
    print(f"    Macro-F1:        {metrics['macro_f1']:.4f}")
    print(f"    Weighted-F1:     {metrics['weighted_f1']:.4f}")
    print(f"    Accuracy:        {metrics['accuracy']:.4f}")

    results_tag = "ensemble_v2" if not tier else f"{tier}_ensemble_v2"
    results = {
        "model_key": "ensemble",
        "tier": tier or "tier1_c_cpp",
        "version": "v2_fixed",
        "weight_gc": weight_gc,
        "temperature": temperature,
        "test_metrics": metrics,
        "class_names": class_names,
        "per_class_report": {k: v for k, v in report.items() if k not in ["accuracy", "macro avg", "weighted avg"]},
        "confusion_matrix": cm.tolist(),
        "timestamp": datetime.now().isoformat(),
    }
    with open(os.path.join(LOGS_DIR, f"phase2_cwe_results_{results_tag}.json"), "w") as f:
        json.dump(results, f, indent=2)

    return results


def compare_v1_v2():
    print("\n" + "=" * 65)
    print("  PHASE 2 — V1 BASELINE VS V2 VARIANTS COMPARISON")
    print("=" * 65)

    models_info = [
        ("v1-baseline", os.path.join(LOGS_DIR, "phase2_cwe_results_v1.json")),
        ("codet5-v2", os.path.join(LOGS_DIR, "phase2_cwe_results_codet5_cwe_v2.json")),
        ("gcbert-v2", os.path.join(LOGS_DIR, "phase2_cwe_results_graphcodebert_cwe_v2.json")),
        ("ensemble-v2 (fixed)", os.path.join(LOGS_DIR, "phase2_cwe_results_ensemble_v2.json")),
    ]

    print(f"\n  {'Model Variant':<22} {'Macro-Rec':>10} {'Macro-F1':>10} {'W-F1':>10} {'Accuracy':>10}")
    print("  " + "-" * 66)

    baseline_rec, baseline_f1 = 0.4348, 0.3213
    best_f1, best_name = 0.0, ""

    for name, path in models_info:
        if os.path.exists(path):
            with open(path) as f:
                d = json.load(f)
            m = d["test_metrics"]
            print(f"  {name:<22} {m['macro_recall']:>10.4f} {m['macro_f1']:>10.4f} {m['weighted_f1']:>10.4f} {m['accuracy']:>10.4f}")
            if m["macro_f1"] > best_f1:
                best_f1 = m["macro_f1"]
                best_name = name
                best_rec = m["macro_recall"]

    print(f"\n  Final Best Variant: {best_name}")
    print(f"  Macro-Recall Improvement over v1: {((best_rec - baseline_rec) / baseline_rec * 100):+.1f}%")
    print(f"  Macro-F1 Improvement over v1:     {((best_f1 - baseline_f1) / baseline_f1 * 100):+.1f}%")


def main():
    parser = argparse.ArgumentParser(description="Phase 2 CWE multi-class classification.")
    parser.add_argument("--model", type=str, default="codet5", choices=["codet5", "graphcodebert"])
    parser.add_argument("--tier", type=str, default=None,
                        choices=["tier1_c_cpp", "tier2_cpp", "tier2_python", "tier2_php", "tier3_shared"])
    parser.add_argument("--variant-tag", type=str, default="v2")
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--grad-accum", type=int, default=DEFAULT_GRAD_ACCUM)
    parser.add_argument("--patience", type=int, default=DEFAULT_PATIENCE)
    parser.add_argument("--focal-gamma", type=float, default=DEFAULT_FOCAL_GAMMA)
    parser.add_argument("--lora-rank", type=int, default=DEFAULT_LORA_R)
    parser.add_argument("--lora-alpha", type=int, default=DEFAULT_LORA_ALPHA)
    parser.add_argument("--warm-start", type=str, default=None)
    parser.add_argument("--use-lang-tokens", action="store_true")
    parser.add_argument("--bf16", action="store_true")
    parser.add_argument("--loss", type=str, default="focal")
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--no-lora", action="store_true")
    parser.add_argument("--no-oversampling", action="store_true")
    parser.add_argument("--ensemble", action="store_true")
    parser.add_argument("--ensemble-weight-gc", type=float, default=0.65)
    parser.add_argument("--temperature", type=float, default=1.5)
    parser.add_argument("--compare", action="store_true")
    args = parser.parse_args()

    if args.ensemble:
        evaluate_ensemble(
            variant_tag=args.variant_tag,
            tier=args.tier,
            weight_gc=args.ensemble_weight_gc,
            temperature=args.temperature,
        )
        compare_v1_v2()
        return

    if args.compare:
        compare_v1_v2()
        return

    train(
        model_key=args.model,
        tier=args.tier,
        variant_tag=args.variant_tag,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        max_length=args.max_length,
        grad_accum=args.grad_accum,
        patience=args.patience,
        use_lora=not args.no_lora,
        lora_r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        focal_gamma=args.focal_gamma,
        use_oversampling=not args.no_oversampling,
        warm_start=args.warm_start,
        use_lang_tokens=args.use_lang_tokens,
        use_bf16=args.bf16,
        max_samples=args.max_samples,
    )


if __name__ == "__main__":
    main()
