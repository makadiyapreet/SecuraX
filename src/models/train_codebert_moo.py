"""
train_codebert_moo.py — Phase 2 AIBugHunter-adapted Multi-Objective Optimization (MOO).

Adapted from:
    Fu et al., "AIBugHunter: A Multi-Objective Optimization Framework for Vulnerability
    Identification and Classification", Empirical Software Engineering, 2024.
    (github.com/awsm-research/AIBugHunter)

Architecture:
    - Shared CodeBERT backbone (microsoft/codebert-base)
    - Head 1: 15-class MITRE semantic CWE grouping
    - Head 2: Coarse security vulnerability category (Memory-Safety, Numeric,
              Input-Validation, Access-Crypto, Resource-Mgmt, Other)
    - Multi-Objective Optimization (MGDA / Frank-Wolfe Min-Norm Solver) to dynamically
      balance Pareto-optimal loss gradients across both classification objectives.

Used in Tier 1 (C/C++) as an additional comparison model.
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
from typing import Dict, List, Tuple

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
from transformers import AutoTokenizer, AutoModel, AutoConfig

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.models.min_norm_solvers import MinNormSolver, gradient_normalizers
from src.data.dataset_cwe import CWE_SEMANTIC_GROUPS
from src.models.train_binary import get_device

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(LOGS_DIR, "train_codebert_moo_v2.log"), mode="w"),
    ],
)
logger = logging.getLogger("CodeBERT_MOO")


# ─── Coarse Category Mapping ───────────────────────────────────────────────
COARSE_CATEGORIES = {
    "Memory-Safety": [
        "Buffer-Overflow", "OOB-Read", "OOB-Write", "Use-After-Free", "Double-Free", "NULL-Deref"
    ],
    "Numeric-Logic": [
        "Integer-Issues", "Race-Condition"
    ],
    "Input-Validation": [
        "Input-Validation", "Path-Traversal"
    ],
    "Access-Crypto": [
        "Access-Control", "Crypto-Issues", "Info-Exposure"
    ],
    "Resource-Mgmt": [
        "Resource-Mgmt"
    ],
    "Other-Security": [
        "Other-Security"
    ],
}

COARSE_NAMES = list(COARSE_CATEGORIES.keys())
SEMANTIC_TO_COARSE = {}
for coarse_idx, (coarse_name, groups) in enumerate(COARSE_CATEGORIES.items()):
    for g in groups:
        SEMANTIC_TO_COARSE[g] = coarse_idx


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


# ─── Classification Heads ───────────────────────────────────────────────────
class ClassificationHead(nn.Module):
    def __init__(self, hidden_size: int, num_labels: int, dropout: float = 0.1):
        super().__init__()
        self.dense = nn.Linear(hidden_size, hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.out_proj = nn.Linear(hidden_size, num_labels)

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        x = self.dropout(features)
        x = self.dense(x)
        x = torch.tanh(x)
        x = self.dropout(x)
        x = self.out_proj(x)
        return x


# ─── Model: Shared CodeBERT + Multi-Objective Heads ─────────────────────────
class CodeBERTMOO(nn.Module):
    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        num_cwe: int = 15,
        num_coarse: int = 6,
    ):
        super().__init__()
        self.config = AutoConfig.from_pretrained(model_name)
        self.encoder = AutoModel.from_pretrained(model_name, config=self.config)
        hidden_size = self.config.hidden_size

        self.cwe_head = ClassificationHead(hidden_size, num_cwe)
        self.coarse_head = ClassificationHead(hidden_size, num_coarse)

    def get_representation(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Use <s> token representation (index 0)
        rep = outputs.last_hidden_state[:, 0, :]
        return rep

    def forward_heads(self, rep: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        cwe_logits = self.cwe_head(rep)
        coarse_logits = self.coarse_head(rep)
        return cwe_logits, coarse_logits

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        rep = self.get_representation(input_ids, attention_mask)
        return self.forward_heads(rep)


# ─── Dataset ─────────────────────────────────────────────────────────────────
class MOODataset(Dataset):
    def __init__(
        self,
        df: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
        class_names: List[str] = None,
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.codes = df["func_before"].astype(str).tolist()
        self.cwe_labels = df["cwe_label"].astype(int).tolist()
        self.coarse_labels = [
            SEMANTIC_TO_COARSE[class_names[lbl]] for lbl in self.cwe_labels
        ]

    def __len__(self) -> int:
        return len(self.codes)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        code = self.codes[idx]
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
            "cwe_label": torch.tensor(self.cwe_labels[idx], dtype=torch.long),
            "coarse_label": torch.tensor(self.coarse_labels[idx], dtype=torch.long),
        }


# ─── Training Function ───────────────────────────────────────────────────────
def train_codebert_moo(
    tier: str = "tier1_c_cpp",
    epochs: int = 10,
    lr: float = 2e-4,
    batch_size: int = 16,
    max_length: int = 512,
    patience: int = 4,
    focal_gamma: float = 2.0,
    use_bf16: bool = True,
    max_samples: int = None,
):
    logger.info("=" * 70)
    logger.info("  AIBugHunter Shared-CodeBERT + MOO Multi-Objective Optimization")
    logger.info(f"  Tier: {tier} | Epochs: {epochs} | Batch: {batch_size} | LR: {lr}")
    logger.info(f"  Loss: FocalLoss(gamma={focal_gamma}) + Coarse CE")
    logger.info("=" * 70)

    device = get_device()
    logger.info(f"Using device: {device}")

    # Build Reverse Mapping
    cwe_to_group = {}
    for g, cwes in CWE_SEMANTIC_GROUPS.items():
        for c in cwes:
            cwe_to_group[c] = g

    class_names = list(CWE_SEMANTIC_GROUPS.keys())
    group_to_idx = {name: idx for idx, name in enumerate(class_names)}

    # Load splits
    tier_dir = os.path.join(PROCESSED_DIR, tier, "cwe")
    train_df = pd.read_csv(os.path.join(tier_dir, "train.csv"))
    val_df = pd.read_csv(os.path.join(tier_dir, "val.csv"))
    test_df = pd.read_csv(os.path.join(tier_dir, "test.csv"))

    for df in [train_df, val_df, test_df]:
        df["group"] = df["cwe_id"].map(lambda c: cwe_to_group.get(str(c).strip(), "Other-Security"))
        df["cwe_label"] = df["group"].map(group_to_idx)

    if max_samples and len(train_df) > max_samples:
        train_df = train_df.groupby("cwe_label", group_keys=False).apply(
            lambda x: x.sample(n=max(1, int(len(x) * (max_samples / len(train_df)))), random_state=42)
        )
        logger.info(f"Subsampled train set to {len(train_df)} samples")

    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")

    train_ds = MOODataset(train_df, tokenizer, max_length, class_names)
    val_ds = MOODataset(val_df, tokenizer, max_length, class_names)
    test_ds = MOODataset(test_df, tokenizer, max_length, class_names)

    # WeightedRandomSampler for minority oversampling
    label_counts = train_df["cwe_label"].value_counts().to_dict()
    weights = [1.0 / (label_counts.get(lbl, 1) ** 0.5) for lbl in train_df["cwe_label"]]
    sampler = WeightedRandomSampler(weights, num_samples=len(weights), replacement=True)

    train_loader = DataLoader(train_ds, batch_size=batch_size, sampler=sampler, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=0)

    # Model & Losses
    model = CodeBERTMOO("microsoft/codebert-base", num_cwe=len(class_names), num_coarse=len(COARSE_NAMES))
    model.to(device)

    # Calculate class weights for Focal Loss
    total = len(train_df)
    cw = torch.tensor(
        [total / (len(class_names) * max(1, label_counts.get(i, 1))) for i in range(len(class_names))],
        dtype=torch.float32,
        device=device,
    )
    cw = torch.clamp(cw, max=10.0)
    cwe_loss_fn = FocalLoss(weight=cw, gamma=focal_gamma).to(device)
    coarse_loss_fn = nn.CrossEntropyLoss().to(device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs)

    save_dir = os.path.join(MODELS_DIR, f"phase2_{tier}_moo_codebert")
    os.makedirs(save_dir, exist_ok=True)

    best_val_macro_f1 = 0.0
    best_epoch = 0
    epochs_no_improve = 0

    use_cuda = (device.type == "cuda")
    scaler = torch.amp.GradScaler("cuda", enabled=(use_cuda and use_bf16))

    # ── Epoch Loop ─────────────────────────────────────────────────────────
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        start_time = time.time()

        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            cwe_labels = batch["cwe_label"].to(device)
            coarse_labels = batch["coarse_label"].to(device)

            optimizer.zero_grad()

            # Forward encoder to get shared representation
            rep = model.get_representation(input_ids, attention_mask)
            rep_var = rep.detach().clone().requires_grad_(True)

            # Compute gradients w.r.t shared representation
            cwe_logits, coarse_logits = model.forward_heads(rep_var)
            l_cwe = cwe_loss_fn(cwe_logits, cwe_labels)
            l_coarse = coarse_loss_fn(coarse_logits, coarse_labels)

            # Gradient for task 1 (CWE 15-class)
            grad_cwe = torch.autograd.grad(l_cwe, rep_var, retain_graph=True)[0]
            # Gradient for task 2 (Coarse Category)
            grad_coarse = torch.autograd.grad(l_coarse, rep_var)[0]

            # Min-Norm Frank-Wolfe Solver for Pareto weights
            grads = [grad_cwe.view(-1), grad_coarse.view(-1)]
            scale, _ = MinNormSolver.find_min_norm_element(grads)
            alpha_cwe = float(scale[0])
            alpha_coarse = float(scale[1])

            # Backpropagate through the entire network using Pareto scales
            cwe_logits_full, coarse_logits_full = model.forward_heads(rep)
            loss_cwe_full = cwe_loss_fn(cwe_logits_full, cwe_labels)
            loss_coarse_full = coarse_loss_fn(coarse_logits_full, coarse_labels)
            combined_loss = alpha_cwe * loss_cwe_full + alpha_coarse * loss_coarse_full

            combined_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            total_loss += combined_loss.item()

        scheduler.step()
        epoch_time = time.time() - start_time
        avg_train_loss = total_loss / max(1, len(train_loader))

        # ── Validation ─────────────────────────────────────────────────────
        model.eval()
        val_preds, val_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                cwe_labels = batch["cwe_label"].to(device)
                cwe_logits, _ = model(input_ids, attention_mask)
                preds = cwe_logits.argmax(dim=-1).cpu().numpy()
                val_preds.extend(preds)
                val_targets.extend(cwe_labels.cpu().numpy())

        val_macro_f1 = f1_score(val_targets, val_preds, average="macro", zero_division=0)
        val_macro_rec = recall_score(val_targets, val_preds, average="macro", zero_division=0)
        val_acc = accuracy_score(val_targets, val_preds)

        logger.info(
            f"Epoch {epoch:02d}/{epochs:02d} ({epoch_time:.0f}s) | "
            f"Train Loss: {avg_train_loss:.4f} | Val Rec: {val_macro_rec:.4f} | "
            f"Val Macro-F1: {val_macro_f1:.4f} | Val Acc: {val_acc:.4f}"
        )

        if val_macro_f1 > best_val_macro_f1:
            best_val_macro_f1 = val_macro_f1
            best_epoch = epoch
            epochs_no_improve = 0
            torch.save(model.state_dict(), os.path.join(save_dir, "pytorch_model.bin"))
            tokenizer.save_pretrained(save_dir)
            with open(os.path.join(save_dir, "training_config.json"), "w") as f:
                json.dump(
                    {
                        "model": "codebert_moo",
                        "tier": tier,
                        "best_epoch": best_epoch,
                        "best_val_macro_f1": best_val_macro_f1,
                        "class_names": class_names,
                        "focal_gamma": focal_gamma,
                        "lr": lr,
                    },
                    f,
                    indent=2,
                )
            logger.info(f"  --> Saved new best model checkpoint (Val Macro-F1: {best_val_macro_f1:.4f})")
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break

    # ── Test Evaluation ────────────────────────────────────────────────────
    logger.info("Evaluating best model checkpoint on Test Set...")
    model.load_state_dict(torch.load(os.path.join(save_dir, "pytorch_model.bin"), map_location=device))
    model.eval()

    test_preds, test_targets, test_logits_list = [], [], []
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            cwe_labels = batch["cwe_label"].to(device)
            cwe_logits, _ = model(input_ids, attention_mask)
            test_logits_list.append(cwe_logits.cpu())
            preds = cwe_logits.argmax(dim=-1).cpu().numpy()
            test_preds.extend(preds)
            test_targets.extend(cwe_labels.cpu().numpy())

    all_logits = torch.cat(test_logits_list, dim=0)
    test_metrics = {
        "macro_recall": recall_score(test_targets, test_preds, average="macro", zero_division=0),
        "macro_precision": precision_score(test_targets, test_preds, average="macro", zero_division=0),
        "macro_f1": f1_score(test_targets, test_preds, average="macro", zero_division=0),
        "weighted_f1": f1_score(test_targets, test_preds, average="weighted", zero_division=0),
        "accuracy": accuracy_score(test_targets, test_preds),
    }

    report = classification_report(test_targets, test_preds, target_names=class_names, zero_division=0, output_dict=True)
    cm = confusion_matrix(test_targets, test_preds)

    logger.info("=" * 60)
    logger.info("  CodeBERT-MOO Test Results:")
    logger.info(f"  Macro-Recall:    {test_metrics['macro_recall']:.4f}")
    logger.info(f"  Macro-F1:        {test_metrics['macro_f1']:.4f}")
    logger.info(f"  Weighted-F1:     {test_metrics['weighted_f1']:.4f}")
    logger.info(f"  Accuracy:        {test_metrics['accuracy']:.4f}")
    logger.info("=" * 60)

    # Save results
    results_path = os.path.join(LOGS_DIR, f"phase2_cwe_results_moo_codebert_{tier}.json")
    results_data = {
        "model": "codebert_moo",
        "tier": tier,
        "best_epoch": best_epoch,
        "test_metrics": test_metrics,
        "class_names": class_names,
        "per_class_report": {k: v for k, v in report.items() if k not in ["accuracy", "macro avg", "weighted avg"]},
        "confusion_matrix": cm.tolist(),
        "timestamp": datetime.now().isoformat(),
    }
    with open(results_path, "w") as f:
        json.dump(results_data, f, indent=2)

    torch.save(
        {"logits": all_logits, "labels": torch.tensor(test_targets)},
        os.path.join(LOGS_DIR, f"test_logits_codebert_moo_{tier}.pt"),
    )
    logger.info(f"Results saved to {results_path}")
    return results_data


def main():
    parser = argparse.ArgumentParser(description="Train CodeBERT-MOO adapted from AIBugHunter.")
    parser.add_argument("--tier", type=str, default="tier1_c_cpp", choices=["tier1_c_cpp"])
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--patience", type=int, default=4)
    parser.add_argument("--focal-gamma", type=float, default=2.0)
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--bf16", action="store_true")
    args = parser.parse_args()

    train_codebert_moo(
        tier=args.tier,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        max_length=args.max_length,
        patience=args.patience,
        focal_gamma=args.focal_gamma,
        use_bf16=args.bf16,
        max_samples=args.max_samples,
    )


if __name__ == "__main__":
    main()
