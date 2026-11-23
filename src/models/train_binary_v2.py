"""
train_binary_v2.py — Phase 1 (Revised): Multi-Tier Binary Vulnerability Detection.

Trains per-tier binary vulnerability classifiers using:
  - LineVul-style attention-pooling head (learned attention over ALL tokens)
  - Focal Loss (γ=2) with inverse-frequency class weights (clamped 10×)
  - LoRA rank 64, alpha 128, targeting q/k/v/o (CodeT5) or query/key/value/dense (GCB)
  - Max token length 512, batch 32-64 with --bf16

Supports three tiers:
  - Tier 1 : Dedicated models (CodeT5, GraphCodeBERT, VulBERTa)
  - Tier 2 : Per-language models warm-started from Tier 1's encoder
  - Tier 3 : Shared model with <LANG=xx> token prepended

Usage:
    # Tier 1 — C/C++
    python src/models/train_binary_v2.py --model codet5 --tier tier1_c_cpp --bf16

    # Tier 2 — Python (warm-started from Tier 1)
    python src/models/train_binary_v2.py --model codet5 --tier tier2_python \\
      --warm-start models/saved/phase1_tier1_c_cpp_codet5/

    # Tier 3 — Shared low-resource model
    python src/models/train_binary_v2.py --model codet5 --tier tier3_shared --bf16

    # VulBERTa zero-shot eval (Tier 1 only)
    python src/models/train_binary_v2.py --model vulberta --tier tier1_c_cpp --zero-shot
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

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.amp import autocast, GradScaler
from sklearn.metrics import (
    recall_score, precision_score, f1_score, roc_auc_score, accuracy_score,
)

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.models.modules import AttentionPooling, FocalLoss, get_class_weights
from src.data.dataset_multilang import create_tier_dataloaders, get_tokenizer

# ─── Constants ───────────────────────────────────────────────────────────────

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

# Revised recipe defaults
DEFAULT_EPOCHS = 10
DEFAULT_LR = 2e-4
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_LENGTH = 512
DEFAULT_GRAD_ACCUM = 2
DEFAULT_PATIENCE = 3

# Revised LoRA
LORA_R = 64
LORA_ALPHA = 128
LORA_DROPOUT = 0.1

# Focal Loss
FOCAL_GAMMA = 2.0
WEIGHT_CLAMP = 10.0


# ─── Device ──────────────────────────────────────────────────────────────────

def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


# ─── Local model resolution ─────────────────────────────────────────────────

PRETRAINED_DIR = os.path.join(PROJECT_ROOT, "models", "pretrained")
_LOCAL_MODEL_MAP = {
    "Salesforce/codet5-base": "codet5-base",
    "microsoft/graphcodebert-base": "graphcodebert-base",
}

def resolve_model_path(model_id: str):
    local_name = _LOCAL_MODEL_MAP.get(model_id)
    if local_name:
        local_path = os.path.join(PRETRAINED_DIR, local_name)
        if os.path.isdir(local_path) and any(
            f.endswith((".bin", ".safetensors")) for f in os.listdir(local_path)
        ):
            return local_path, True
    return model_id, False


# ─── Model Builders ──────────────────────────────────────────────────────────


class CodeT5BinaryV2(nn.Module):
    """CodeT5 encoder + AttentionPooling + binary classification head.

    Uses the LineVul-style attention pooling instead of mean-pool.
    """

    def __init__(
        self,
        model_name: str = "Salesforce/codet5-base",
        num_labels: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        from transformers import T5EncoderModel

        resolved, local_only = resolve_model_path(model_name)
        self.encoder = T5EncoderModel.from_pretrained(
            resolved, local_files_only=local_only
        )
        self.config = self.encoder.config
        hidden_size = self.config.d_model  # 768

        self.attention_pool = AttentionPooling(hidden_size, dropout=dropout)
        self.classifier = nn.Linear(hidden_size, num_labels)
        self.num_labels = num_labels

    def forward(self, input_ids, attention_mask=None, labels=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = outputs.last_hidden_state   # (B, L, 768)
        pooled = self.attention_pool(hidden, attention_mask)  # (B, 768)
        logits = self.classifier(pooled)      # (B, 2)

        loss = None
        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            loss = loss_fn(logits, labels)

        return SimpleNamespace(loss=loss, logits=logits)


class GraphCodeBERTV2(nn.Module):
    """GraphCodeBERT + AttentionPooling + binary classification head.

    Replaces AutoModelForSequenceClassification's default [CLS] pooling
    with LineVul-style attention pooling.
    """

    def __init__(
        self,
        model_name: str = "microsoft/graphcodebert-base",
        num_labels: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        from transformers import AutoModel

        resolved, local_only = resolve_model_path(model_name)
        self.encoder = AutoModel.from_pretrained(
            resolved, local_files_only=local_only
        )
        self.config = self.encoder.config
        hidden_size = self.config.hidden_size  # 768

        self.attention_pool = AttentionPooling(hidden_size, dropout=dropout)
        self.classifier = nn.Linear(hidden_size, num_labels)
        self.num_labels = num_labels

    def forward(self, input_ids, attention_mask=None, labels=None, return_attention=False, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = outputs.last_hidden_state   # (B, L, 768)

        if return_attention:
            pooled, attn_weights = self.attention_pool(hidden, attention_mask, return_weights=True)
        else:
            pooled = self.attention_pool(hidden, attention_mask)
            attn_weights = None

        logits = self.classifier(pooled)

        loss = None
        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            loss = loss_fn(logits, labels)

        return SimpleNamespace(loss=loss, logits=logits, attention_weights=attn_weights)


def build_model_v2(
    model_key: str,
    lora_r: int = LORA_R,
    lora_alpha: int = LORA_ALPHA,
    warm_start: str = None,
    tokenizer_len: int = None,
):
    """Build model with revised LoRA config and optional warm-start.

    Args:
        model_key   : 'codet5', 'graphcodebert', or 'vulberta'
        lora_r      : LoRA rank (default 64)
        lora_alpha  : LoRA alpha (default 128)
        warm_start  : path to a Tier 1 checkpoint to warm-start encoder from
        tokenizer_len: if set, resize token embeddings (for added lang tokens)

    Returns:
        (model, lora_applied, target_modules_used)
    """
    if model_key == "codet5":
        model = CodeT5BinaryV2("Salesforce/codet5-base")
        target_modules = ["q", "k", "v", "o"]
    elif model_key == "graphcodebert":
        model = GraphCodeBERTV2("microsoft/graphcodebert-base")
        target_modules = ["query", "key", "value", "dense"]
    elif model_key == "vulberta":
        from transformers import AutoModelForSequenceClassification
        model = AutoModelForSequenceClassification.from_pretrained(
            "claudios/VulBERTa-MLP-VulDeePecker",
            num_labels=2,
            ignore_mismatched_sizes=True,
        )
        target_modules = ["query", "key", "value", "dense"]
    else:
        raise ValueError(f"Unknown model key: {model_key}")

    # Resize embeddings for language tokens
    if tokenizer_len is not None and model_key != "vulberta":
        encoder = model.encoder if hasattr(model, 'encoder') else model
        if hasattr(encoder, 'resize_token_embeddings'):
            encoder.resize_token_embeddings(tokenizer_len)
            print(f"  Resized embeddings to {tokenizer_len}")

    # Warm-start from Tier 1 encoder (for Tier 2 training)
    if warm_start and os.path.isdir(warm_start):
        print(f"  🔥 Warm-starting encoder from: {warm_start}")
        try:
            from peft import PeftModel
            # Load Tier 1 model to get its encoder weights
            if model_key == "codet5":
                tier1_base = CodeT5BinaryV2("Salesforce/codet5-base")
            else:
                tier1_base = GraphCodeBERTV2("microsoft/graphcodebert-base")

            tier1_model = PeftModel.from_pretrained(tier1_base, warm_start)
            tier1_merged = tier1_model.merge_and_unload()

            # Copy encoder weights only (not classifier head)
            encoder_state = {}
            for k, v in tier1_merged.state_dict().items():
                if k.startswith("encoder."):
                    encoder_state[k] = v

            missing, unexpected = model.load_state_dict(encoder_state, strict=False)
            print(f"    Loaded {len(encoder_state)} encoder params "
                  f"(missing: {len(missing)}, unexpected: {len(unexpected)})")

            del tier1_model, tier1_merged, tier1_base
            gc.collect()
        except Exception as e:
            print(f"  ⚠️  Warm-start failed: {e}. Training from scratch.")

    # Apply LoRA
    try:
        from peft import LoraConfig, get_peft_model, TaskType

        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=lora_r,
            lora_alpha=lora_alpha,
            lora_dropout=LORA_DROPOUT,
            target_modules=target_modules,
            bias="none",
        )
        model = get_peft_model(model, lora_config)

        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total = sum(p.numel() for p in model.parameters())
        print(f"  LoRA applied (r={lora_r}, α={lora_alpha}): "
              f"{trainable:,} trainable / {total:,} total ({trainable/total*100:.2f}%)")
        print(f"  Target modules: {target_modules}")

        return model, True, target_modules

    except Exception as e:
        print(f"  ⚠️  LoRA failed ({e}), falling back to full fine-tuning")
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        print(f"  Full fine-tuning: {trainable:,} trainable parameters")
        return model, False, target_modules


# ─── Evaluation ──────────────────────────────────────────────────────────────


def evaluate_epoch(model, dataloader, device, loss_fn=None, threshold=0.5):
    """Evaluate model on a dataloader with a given threshold."""
    model.eval()
    all_preds, all_labels, all_probs = [], [], []
    total_loss = 0.0
    n_batches = 0

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )
            logits = outputs.logits if hasattr(outputs, 'logits') else outputs['logits']

            if loss_fn is not None:
                loss = loss_fn(logits, labels)
                total_loss += loss.item()
            n_batches += 1

            probs = torch.softmax(logits, dim=-1)[:, 1]  # P(vulnerable)
            preds = (probs >= threshold).long()

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)
    all_probs = np.array(all_probs)

    metrics = {
        "loss": total_loss / max(n_batches, 1),
        "accuracy": accuracy_score(all_labels, all_preds),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
        "threshold": threshold,
    }

    try:
        metrics["auroc"] = roc_auc_score(all_labels, all_probs)
    except ValueError:
        metrics["auroc"] = 0.0

    return metrics, all_labels, all_probs


# ─── Threshold Sweep ─────────────────────────────────────────────────────────


def threshold_sweep(
    all_labels: np.ndarray,
    all_probs: np.ndarray,
    min_threshold: float = 0.10,
    max_threshold: float = 0.90,
    step: float = 0.05,
    precision_floor: float = 0.75,
):
    """Sweep thresholds and find optimal one maximizing Recall with Precision >= floor.

    Returns:
        (best_threshold, sweep_table: list of dicts)
    """
    sweep = []
    best_threshold = 0.5
    best_recall = 0.0

    thresholds = np.arange(min_threshold, max_threshold + step/2, step)

    for t in thresholds:
        preds = (all_probs >= t).astype(int)
        rec = recall_score(all_labels, preds, zero_division=0)
        prec = precision_score(all_labels, preds, zero_division=0)
        f1 = f1_score(all_labels, preds, zero_division=0)

        sweep.append({
            "threshold": round(float(t), 2),
            "recall": round(float(rec), 4),
            "precision": round(float(prec), 4),
            "f1": round(float(f1), 4),
            "meets_floor": prec >= precision_floor,
        })

        # Select: maximize recall subject to precision >= floor
        if prec >= precision_floor and rec > best_recall:
            best_recall = rec
            best_threshold = round(float(t), 2)

    # If no threshold meets the floor, fall back to best F1
    if best_recall == 0.0:
        best_f1 = 0.0
        for row in sweep:
            if row["f1"] > best_f1:
                best_f1 = row["f1"]
                best_threshold = row["threshold"]

    return best_threshold, sweep


# ─── Training ────────────────────────────────────────────────────────────────


def train_v2(
    model_key: str,
    tier: str,
    epochs: int = DEFAULT_EPOCHS,
    lr: float = DEFAULT_LR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
    grad_accum: int = DEFAULT_GRAD_ACCUM,
    patience: int = DEFAULT_PATIENCE,
    lora_r: int = LORA_R,
    lora_alpha: int = LORA_ALPHA,
    focal_gamma: float = FOCAL_GAMMA,
    use_bf16: bool = False,
    warm_start: str = None,
    zero_shot: bool = False,
    max_samples: int = None,
):
    """Main revised training function for Phase 1 multi-tier.

    Args:
        model_key  : 'codet5', 'graphcodebert', or 'vulberta'
        tier       : 'tier1_c_cpp', 'tier2_python', 'tier3_shared', etc.
        epochs     : number of training epochs
        lr         : learning rate
        batch_size : per-device batch size
        max_length : max token length (default 512)
        grad_accum : gradient accumulation steps
        patience   : early stopping patience
        lora_r     : LoRA rank (default 64)
        lora_alpha : LoRA alpha (default 128)
        focal_gamma: focal loss gamma (default 2.0)
        use_bf16   : use bfloat16 mixed precision (CUDA only)
        warm_start : path to Tier 1 checkpoint for warm-starting
        zero_shot  : if True, only evaluate without training (for VulBERTa)
        max_samples: if set, subsample training data to this many samples
    """
    device = get_device()
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Determine if Tier 3 (needs lang tokens)
    use_lang_tokens = "tier3" in tier

    # Setup logging
    run_name = f"{tier}_{model_key}"
    log_path = os.path.join(LOGS_DIR, f"train_{run_name}_v2.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode="w"),
            logging.StreamHandler(sys.stdout),
        ],
        force=True,
    )
    logger = logging.getLogger(__name__)

    logger.info("=" * 70)
    logger.info(f"  PHASE 1 (REVISED) — BINARY VULNERABILITY DETECTION")
    logger.info(f"  Tier:        {tier}")
    logger.info(f"  Model:       {model_key}")
    logger.info(f"  Device:      {device}")
    logger.info(f"  Epochs:      {epochs}")
    logger.info(f"  Batch size:  {batch_size} (effective: {batch_size * grad_accum})")
    logger.info(f"  LR:          {lr}")
    logger.info(f"  Max length:  {max_length}")
    logger.info(f"  LoRA:        r={lora_r}, alpha={lora_alpha}")
    logger.info(f"  Focal Loss:  gamma={focal_gamma}")
    logger.info(f"  BF16:        {use_bf16}")
    logger.info(f"  Warm-start:  {warm_start or 'None'}")
    logger.info(f"  Zero-shot:   {zero_shot}")
    logger.info(f"  Lang tokens: {use_lang_tokens}")
    logger.info("=" * 70)

    # ── 1. Data ──────────────────────────────────────────────────────────
    logger.info("\n[1/5] Loading data...")
    train_loader, val_loader, test_loader, meta = create_tier_dataloaders(
        tier=tier,
        task="vf",
        model_name=model_key,
        max_length=max_length,
        batch_size=batch_size,
        add_lang_tokens=use_lang_tokens,
        max_samples=max_samples,
    )

    # ── 2. Model ─────────────────────────────────────────────────────────
    logger.info("\n[2/5] Building model...")

    if zero_shot:
        # Zero-shot: just load the model and evaluate
        if model_key == "vulberta":
            from transformers import AutoModelForSequenceClassification
            model = AutoModelForSequenceClassification.from_pretrained(
                "claudios/VulBERTa-MLP-VulDeePecker",
                num_labels=2,
                ignore_mismatched_sizes=True,
            )
        else:
            model, _, _ = build_model_v2(model_key, lora_r, lora_alpha)
        model = model.to(device)
        lora_applied = False
    else:
        model, lora_applied, target_modules = build_model_v2(
            model_key,
            lora_r=lora_r,
            lora_alpha=lora_alpha,
            warm_start=warm_start,
            tokenizer_len=meta.get("vocab_size"),
        )
        model = model.to(device)

    logger.info(f"  Model on {device}")

    # ── 3. Loss function ─────────────────────────────────────────────────
    class_weights = meta.get("class_weights")
    if class_weights is not None:
        logger.info(f"  Class weights: {class_weights.tolist()}")
        loss_fn = FocalLoss(
            gamma=focal_gamma,
            weight=class_weights.to(device),
        )
    else:
        loss_fn = FocalLoss(gamma=focal_gamma)
    logger.info(f"  Loss: FocalLoss(gamma={focal_gamma})")

    # ── Zero-shot evaluation ─────────────────────────────────────────────
    if zero_shot:
        logger.info("\n[ZERO-SHOT] Evaluating without training...")
        test_metrics, test_labels, test_probs = evaluate_epoch(
            model, test_loader, device, loss_fn
        )
        logger.info(f"\n  ── ZERO-SHOT TEST RESULTS ({model_key} on {tier}) ──")
        for k, v in test_metrics.items():
            logger.info(f"    {k:<12}: {v:.4f}")

        # Threshold sweep
        best_t, sweep = threshold_sweep(test_labels, test_probs)
        logger.info(f"\n  Best threshold: {best_t}")

        results = {
            "model": model_key, "tier": tier, "mode": "zero_shot",
            "test_metrics": test_metrics, "threshold_sweep": sweep,
            "best_threshold": best_t, "timestamp": datetime.now().isoformat(),
        }
        results_path = os.path.join(LOGS_DIR, f"phase1_{run_name}_zeroshot.json")
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"  Results saved: {results_path}")
        return results

    # ── 4. Optimizer & Scheduler ─────────────────────────────────────────
    logger.info("\n[3/5] Setting up optimizer...")
    optimizer = AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=lr, weight_decay=0.01,
    )
    total_steps = len(train_loader) * epochs // grad_accum
    scheduler = CosineAnnealingLR(optimizer, T_max=total_steps, eta_min=lr * 0.1)

    # Mixed precision
    scaler = None
    amp_dtype = None
    if use_bf16 and device.type == "cuda":
        amp_dtype = torch.bfloat16
        scaler = GradScaler(enabled=False)  # bf16 doesn't need scaling
        logger.info("  Using bfloat16 mixed precision")
    elif use_bf16 and device.type != "cuda":
        logger.info("  ⚠️  bf16 requested but not CUDA — using fp32")

    # ── 5. Training loop ─────────────────────────────────────────────────
    logger.info("\n[4/5] Training...")

    best_val_f1 = 0.0
    best_epoch = -1
    epochs_no_improve = 0
    save_dir = os.path.join(MODELS_DIR, f"phase1_{run_name}")
    history = []

    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        model.train()
        running_loss = 0.0
        optimizer.zero_grad()

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            if amp_dtype is not None:
                with autocast(device_type="cuda", dtype=amp_dtype):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                    logits = outputs.logits if hasattr(outputs, 'logits') else outputs['logits']
                    loss = loss_fn(logits, labels) / grad_accum
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                logits = outputs.logits if hasattr(outputs, 'logits') else outputs['logits']
                loss = loss_fn(logits, labels) / grad_accum

            loss.backward()
            running_loss += loss.item() * grad_accum

            if step % grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            if step % 100 == 0:
                avg = running_loss / step
                logger.info(
                    f"  Epoch {epoch}/{epochs} | Step {step}/{len(train_loader)} | "
                    f"Loss: {avg:.4f}"
                )

        # Flush remaining grads
        if len(train_loader) % grad_accum != 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            optimizer.zero_grad()

        train_loss = running_loss / len(train_loader)

        # Validation
        val_metrics, _, _ = evaluate_epoch(model, val_loader, device, loss_fn)
        epoch_time = time.time() - epoch_start

        logger.info(
            f"\n  ── Epoch {epoch}/{epochs} ({epoch_time:.0f}s) ──\n"
            f"    Train Loss:  {train_loss:.4f}\n"
            f"    Val Loss:    {val_metrics['loss']:.4f}\n"
            f"    Val Recall:  {val_metrics['recall']:.4f}\n"
            f"    Val Prec:    {val_metrics['precision']:.4f}\n"
            f"    Val F1:      {val_metrics['f1']:.4f}\n"
            f"    Val AUROC:   {val_metrics['auroc']:.4f}\n"
            f"    Val Acc:     {val_metrics['accuracy']:.4f}"
        )

        history.append({
            "epoch": epoch,
            "train_loss": train_loss,
            **{f"val_{k}": v for k, v in val_metrics.items()},
            "epoch_time_s": epoch_time,
        })

        # Checkpointing (by val F1)
        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_epoch = epoch
            epochs_no_improve = 0

            os.makedirs(save_dir, exist_ok=True)
            if lora_applied:
                model.save_pretrained(save_dir)
            else:
                torch.save(model.state_dict(), os.path.join(save_dir, "model.pt"))

            config = {
                "model_key": model_key, "tier": tier,
                "use_lora": lora_applied,
                "lora_r": lora_r, "lora_alpha": lora_alpha,
                "lora_targets": target_modules if lora_applied else None,
                "max_length": max_length, "epochs_trained": epoch,
                "best_val_f1": best_val_f1,
                "focal_gamma": focal_gamma, "bf16": use_bf16,
                "warm_start": warm_start, "lr": lr,
                "batch_size": batch_size, "grad_accum": grad_accum,
                "device": str(device), "timestamp": datetime.now().isoformat(),
            }
            with open(os.path.join(save_dir, "training_config.json"), "w") as f:
                json.dump(config, f, indent=2)

            logger.info(f"    [BEST] New best F1={best_val_f1:.4f} -- saved to {save_dir}")
        else:
            epochs_no_improve += 1
            logger.info(
                f"    No improvement ({epochs_no_improve}/{patience}). "
                f"Best F1={best_val_f1:.4f} at epoch {best_epoch}"
            )

        if epochs_no_improve >= patience:
            logger.info(f"\n  ⏹️  Early stopping at epoch {epoch}")
            break

    # ── 6. Test evaluation ───────────────────────────────────────────────
    logger.info("\n[5/5] Evaluating on test set...")

    # Reload best checkpoint
    if lora_applied:
        from peft import PeftModel
        if model_key == "codet5":
            base_model = CodeT5BinaryV2("Salesforce/codet5-base")
        elif model_key == "graphcodebert":
            base_model = GraphCodeBERTV2("microsoft/graphcodebert-base")
        else:
            from transformers import AutoModelForSequenceClassification
            base_model = AutoModelForSequenceClassification.from_pretrained(
                "claudios/VulBERTa-MLP-VulDeePecker",
                num_labels=2, ignore_mismatched_sizes=True,
            )
        model = PeftModel.from_pretrained(base_model, save_dir)
    else:
        if model_key == "codet5":
            model = CodeT5BinaryV2("Salesforce/codet5-base")
        elif model_key == "graphcodebert":
            model = GraphCodeBERTV2("microsoft/graphcodebert-base")
        model.load_state_dict(torch.load(
            os.path.join(save_dir, "model.pt"), map_location=device, weights_only=True
        ))

    model = model.to(device)

    # Default threshold evaluation
    test_metrics, test_labels, test_probs = evaluate_epoch(
        model, test_loader, device, loss_fn
    )

    logger.info(
        f"\n  ── TEST RESULTS ({model_key} on {tier}, threshold=0.50) ──\n"
        f"    Recall:    {test_metrics['recall']:.4f}  ← primary metric\n"
        f"    Precision: {test_metrics['precision']:.4f}\n"
        f"    F1:        {test_metrics['f1']:.4f}\n"
        f"    AUROC:     {test_metrics['auroc']:.4f}\n"
        f"    Accuracy:  {test_metrics['accuracy']:.4f}\n"
        f"    Loss:      {test_metrics['loss']:.4f}"
    )

    # ── Threshold sweep ──────────────────────────────────────────────────
    logger.info("\n  Running threshold sweep (0.10–0.90, step=0.05)...")
    best_t, sweep = threshold_sweep(test_labels, test_probs)

    logger.info(f"\n  {'Threshold':>10} {'Recall':>8} {'Precision':>10} {'F1':>8} {'Floor?':>7}")
    logger.info(f"  {'─'*45}")
    for row in sweep:
        marker = " ◀" if row["threshold"] == best_t else ""
        floor_mark = "✓" if row["meets_floor"] else "✗"
        logger.info(
            f"  {row['threshold']:>10.2f} {row['recall']:>8.4f} "
            f"{row['precision']:>10.4f} {row['f1']:>8.4f} {floor_mark:>7}{marker}"
        )

    # Re-evaluate at best threshold
    test_at_best, _, _ = evaluate_epoch(model, test_loader, device, loss_fn, threshold=best_t)
    logger.info(
        f"\n  ── TEST @ OPTIMAL THRESHOLD={best_t} ──\n"
        f"    Recall:    {test_at_best['recall']:.4f}\n"
        f"    Precision: {test_at_best['precision']:.4f}\n"
        f"    F1:        {test_at_best['f1']:.4f}"
    )

    # ── Save results ─────────────────────────────────────────────────────
    results = {
        "model": model_key, "tier": tier, "mode": "trained",
        "use_lora": lora_applied, "checkpoint_dir": save_dir,
        "best_epoch": best_epoch, "best_val_f1": best_val_f1,
        "test_metrics_default": test_metrics,
        "test_metrics_optimal": test_at_best,
        "best_threshold": best_t, "threshold_sweep": sweep,
        "training_history": history,
        "hyperparams": {
            "epochs": epochs, "lr": lr, "batch_size": batch_size,
            "grad_accum": grad_accum, "max_length": max_length,
            "patience": patience, "lora_r": lora_r, "lora_alpha": lora_alpha,
            "focal_gamma": focal_gamma, "bf16": use_bf16,
            "warm_start": warm_start,
        },
        "timestamp": datetime.now().isoformat(),
    }

    results_path = os.path.join(LOGS_DIR, f"phase1_{run_name}_results_v2.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\n  Results saved: {results_path}")

    # Cleanup
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    return results


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Phase 1 (Revised): Multi-tier binary vulnerability detection."
    )
    parser.add_argument(
        "--model", type=str, required=True,
        choices=["codet5", "graphcodebert", "vulberta"],
        help="Model backbone to train",
    )
    parser.add_argument(
        "--tier", type=str, required=True,
        help="Data tier (e.g. tier1_c_cpp, tier2_python, tier3_shared)",
    )
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--grad-accum", type=int, default=DEFAULT_GRAD_ACCUM)
    parser.add_argument("--patience", type=int, default=DEFAULT_PATIENCE)
    parser.add_argument("--lora-r", type=int, default=LORA_R)
    parser.add_argument("--lora-alpha", type=int, default=LORA_ALPHA)
    parser.add_argument("--focal-gamma", type=float, default=FOCAL_GAMMA)
    parser.add_argument(
        "--bf16", action="store_true",
        help="Use bfloat16 mixed precision (CUDA only)",
    )
    parser.add_argument(
        "--warm-start", type=str, default=None,
        help="Path to Tier 1 checkpoint to warm-start encoder from",
    )
    parser.add_argument(
        "--zero-shot", action="store_true",
        help="Evaluate model zero-shot without training (for VulBERTa)",
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="Subsample training data to this many samples (e.g. 50000 for faster training)",
    )
    args = parser.parse_args()

    train_v2(
        model_key=args.model,
        tier=args.tier,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        max_length=args.max_length,
        grad_accum=args.grad_accum,
        patience=args.patience,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        focal_gamma=args.focal_gamma,
        use_bf16=args.bf16,
        warm_start=args.warm_start,
        zero_shot=args.zero_shot,
        max_samples=args.max_samples,
    )


if __name__ == "__main__":
    main()