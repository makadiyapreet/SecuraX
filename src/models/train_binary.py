"""
train_binary.py — Fine-tune CodeT5 or GraphCodeBERT on binary vulnerability detection.

Trains a binary classifier (vulnerable vs. non-vulnerable) using LoRA
(via PEFT) for parameter-efficient fine-tuning.

Usage:
    python src/models/train_binary.py --model codet5       [--epochs 5] [--lr 2e-4]
    python src/models/train_binary.py --model graphcodebert [--epochs 5] [--lr 2e-4]

Outputs:
    - Best model checkpoint → models/saved/<model>_binary_best/
    - Training logs → logs/train_<model>_binary.log
"""

<<<<<<< HEAD
import os
=======
# Disable TensorFlow before importing transformers — TF 2.20 causes a
# mutex deadlock ([mutex.cc : 452] RAW: Lock blocking) on macOS when
# loading models via transformers.
import os
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"

>>>>>>> 7861432 (Phase 1 completed)
import sys
import gc
import json
import time
import argparse
import logging
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from sklearn.metrics import (
    recall_score, precision_score, f1_score, roc_auc_score,
    accuracy_score,
)

# Add project root to path
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.data.dataset import create_dataloaders, load_bigvul_dataframe


# ─── Constants ───────────────────────────────────────────────────────────────

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

# Default hyperparameters
DEFAULT_EPOCHS = 5
DEFAULT_LR = 2e-4
DEFAULT_BATCH_SIZE = 16
DEFAULT_MAX_LENGTH = 512
DEFAULT_GRAD_ACCUM = 2       # effective batch = batch_size * grad_accum
DEFAULT_WARMUP_RATIO = 0.1
DEFAULT_PATIENCE = 2         # early stopping patience

# LoRA config
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.1


# ─── Device detection ───────────────────────────────────────────────────────


def get_device() -> torch.device:
    """Get the best available device."""
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


<<<<<<< HEAD
=======
# ─── Local model resolution ──────────────────────────────────────────────────

PRETRAINED_DIR = os.path.join(PROJECT_ROOT, "models", "pretrained")

# Map HuggingFace model IDs to local directory names
_LOCAL_MODEL_MAP = {
    "Salesforce/codet5-base": "codet5-base",
    "microsoft/graphcodebert-base": "graphcodebert-base",
}


def resolve_model_path(model_id: str):
    """Return (path, local_files_only) for model loading.

    Checks models/pretrained/<name>/ for a local copy of the model weights.
    This avoids HuggingFace Hub downloads on systems with SSL issues.
    Returns a tuple: (resolved_path, local_files_only_flag)
    """
    local_name = _LOCAL_MODEL_MAP.get(model_id)
    if local_name:
        local_path = os.path.join(PRETRAINED_DIR, local_name)
        if os.path.isdir(local_path) and any(
            f.endswith((".bin", ".safetensors")) for f in os.listdir(local_path)
        ):
            print(f"  📂 Loading from local: {local_path}")
            return local_path, True
    return model_id, False


>>>>>>> 7861432 (Phase 1 completed)
# ─── Model builders ─────────────────────────────────────────────────────────


class CodeT5BinaryClassifier(nn.Module):
    """CodeT5 encoder + classification head for binary vulnerability detection.

    Uses the encoder from CodeT5-base (T5 encoder) and adds a linear
    classification head on top of the [CLS]-equivalent pooled output.

    Exposes ``self.config`` from the underlying T5EncoderModel so that
    PEFT/LoRA wrappers (which inspect ``config.use_return_dict``) work
    correctly.
    """

    def __init__(self, model_name: str = "Salesforce/codet5-base", num_labels: int = 2):
        super().__init__()
        from transformers import T5EncoderModel

<<<<<<< HEAD
        self.encoder = T5EncoderModel.from_pretrained(model_name)
=======
        resolved, local_only = resolve_model_path(model_name)
        self.encoder = T5EncoderModel.from_pretrained(resolved, local_files_only=local_only)
>>>>>>> 7861432 (Phase 1 completed)
        # Expose encoder config at top level for PEFT compatibility
        self.config = self.encoder.config
        hidden_size = self.config.d_model  # 768 for codet5-base
        self.num_labels = num_labels
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(hidden_size, num_labels)

    def forward(self, input_ids, attention_mask=None, labels=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Pool: use mean of encoder hidden states (weighted by attention mask)
        hidden = outputs.last_hidden_state  # [B, seq_len, hidden]
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()  # [B, seq_len, 1]
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        else:
            pooled = hidden.mean(dim=1)

        pooled = self.dropout(pooled)
        logits = self.classifier(pooled)  # [B, num_labels]

        loss = None
        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            loss = loss_fn(logits, labels)

        # Return a simple namespace so both dict-style and attr-style access work
        from types import SimpleNamespace
        return SimpleNamespace(loss=loss, logits=logits)


def build_model(model_key: str, use_lora: bool = True):
    """Build a model with optional LoRA adapters.

    Args:
        model_key: 'codet5' or 'graphcodebert'
        use_lora: Whether to apply LoRA adapters

    Returns:
        (model, lora_applied: bool)
    """
    if model_key == "codet5":
        model = CodeT5BinaryClassifier("Salesforce/codet5-base", num_labels=2)
        target_modules = ["q", "v"]  # T5 attention projection names
    elif model_key == "graphcodebert":
        from transformers import AutoModelForSequenceClassification
<<<<<<< HEAD
        model = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/graphcodebert-base",
            num_labels=2,
=======
        resolved, local_only = resolve_model_path("microsoft/graphcodebert-base")
        model = AutoModelForSequenceClassification.from_pretrained(
            resolved,
            num_labels=2,
            local_files_only=local_only,
>>>>>>> 7861432 (Phase 1 completed)
        )
        target_modules = ["query", "value"]  # RoBERTa attention projection names
    else:
        raise ValueError(f"Unknown model key: {model_key}")

    if use_lora:
        try:
            from peft import LoraConfig, get_peft_model, TaskType

            lora_config = LoraConfig(
                task_type=TaskType.SEQ_CLS,
                r=LORA_R,
                lora_alpha=LORA_ALPHA,
                lora_dropout=LORA_DROPOUT,
                target_modules=target_modules,
                bias="none",
            )
            model = get_peft_model(model, lora_config)

            # Log trainable params
            trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
            total = sum(p.numel() for p in model.parameters())
            print(f"  LoRA applied: {trainable:,} trainable / {total:,} total "
                  f"({trainable/total*100:.2f}%)")

            return model, True
        except Exception as e:
            print(f"  ⚠️  LoRA failed ({e}), falling back to full fine-tuning")
            # Rebuild without LoRA
            return build_model(model_key, use_lora=False)

    # Full fine-tuning — log param count
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Full fine-tuning: {trainable:,} trainable parameters")
    return model, False


# ─── Training loop ───────────────────────────────────────────────────────────


def evaluate_epoch(model, dataloader, device):
    """Evaluate model on a dataloader. Returns dict of metrics + avg loss."""
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []
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
                labels=labels,
            )

            # Handle different output formats (dict vs named tuple)
            if isinstance(outputs, dict):
                loss = outputs["loss"]
                logits = outputs["logits"]
            else:
                loss = outputs.loss
                logits = outputs.logits

            total_loss += loss.item()
            n_batches += 1

            probs = torch.softmax(logits, dim=-1)[:, 1]  # P(vulnerable)
            preds = (probs >= 0.5).long()

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
    }

    # AUROC — requires both classes present in labels
    try:
        metrics["auroc"] = roc_auc_score(all_labels, all_probs)
    except ValueError:
        metrics["auroc"] = 0.0

    return metrics


def train(
    model_key: str,
    epochs: int = DEFAULT_EPOCHS,
    lr: float = DEFAULT_LR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
    grad_accum: int = DEFAULT_GRAD_ACCUM,
    patience: int = DEFAULT_PATIENCE,
    use_lora: bool = True,
    max_samples: int = None,
):
    """Main training function.

    Args:
        model_key: 'codet5' or 'graphcodebert'
        epochs: Max training epochs
        lr: Learning rate
        batch_size: Per-device batch size
        max_length: Max token sequence length
        grad_accum: Gradient accumulation steps
        patience: Early stopping patience (epochs without val F1 improvement)
        use_lora: Whether to use LoRA (recommended)
        max_samples: If set, subsample the dataset to this total size

    Returns:
        dict with final metrics and checkpoint path
    """
    device = get_device()
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Setup logging
    log_path = os.path.join(LOGS_DIR, f"train_{model_key}_binary.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode="w"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info(f"  PHASE 1 — BINARY VULNERABILITY DETECTION")
    logger.info(f"  Model:       {model_key}")
    logger.info(f"  Device:      {device}")
    logger.info(f"  Epochs:      {epochs}")
    logger.info(f"  Batch size:  {batch_size} (effective: {batch_size * grad_accum})")
    logger.info(f"  LR:          {lr}")
    logger.info(f"  Max length:  {max_length}")
    logger.info(f"  LoRA:        {use_lora}")
    logger.info(f"  Patience:    {patience}")
    logger.info(f"  Max samples: {max_samples or 'all'}")
    logger.info("=" * 60)

    # ── 1. Data ──────────────────────────────────────────────────────────
    logger.info("\n[1/4] Loading data and creating DataLoaders...")
    df = load_bigvul_dataframe()
    train_loader, val_loader, test_loader = create_dataloaders(
        model_name=model_key,
        max_length=max_length,
        batch_size=batch_size,
        df=df,
        max_samples=max_samples,
    )
    del df
    gc.collect()

    # ── 2. Model ─────────────────────────────────────────────────────────
    logger.info("\n[2/4] Building model...")
    model, lora_applied = build_model(model_key, use_lora=use_lora)
    model = model.to(device)
    logger.info(f"  Model on {device}")

    # ── 3. Optimizer & Scheduler ─────────────────────────────────────────
    optimizer = AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=lr,
        weight_decay=0.01,
    )

    total_steps = len(train_loader) * epochs // grad_accum
    scheduler = CosineAnnealingLR(optimizer, T_max=total_steps, eta_min=lr * 0.1)

    logger.info(f"  Optimizer: AdamW (lr={lr}, wd=0.01)")
    logger.info(f"  Scheduler: CosineAnnealing (T_max={total_steps})")

    # ── 4. Training ──────────────────────────────────────────────────────
    logger.info("\n[3/4] Training...")

    best_val_f1 = 0.0
    best_epoch = -1
    epochs_no_improve = 0
    save_dir = os.path.join(MODELS_DIR, f"{model_key}_binary_best")
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

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                labels=labels,
            )

            if isinstance(outputs, dict):
                loss = outputs["loss"]
            else:
                loss = outputs.loss

            loss = loss / grad_accum
            loss.backward()
            running_loss += loss.item() * grad_accum

            if step % grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            # Progress logging every 100 batches
            if step % 100 == 0:
                avg = running_loss / step
                logger.info(
                    f"  Epoch {epoch}/{epochs} | Step {step}/{len(train_loader)} | "
                    f"Loss: {avg:.4f}"
                )

        # Flush remaining gradients
        if len(train_loader) % grad_accum != 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            optimizer.zero_grad()

        train_loss = running_loss / len(train_loader)

        # Validation
        val_metrics = evaluate_epoch(model, val_loader, device)
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

            # Save model
            if lora_applied:
                model.save_pretrained(save_dir)
            else:
                torch.save(model.state_dict(), os.path.join(save_dir, "model.pt"))

            # Save training config
            config = {
                "model_key": model_key,
                "use_lora": lora_applied,
                "lora_r": LORA_R if lora_applied else None,
                "lora_alpha": LORA_ALPHA if lora_applied else None,
                "max_length": max_length,
                "epochs_trained": epoch,
                "best_val_f1": best_val_f1,
                "best_val_recall": val_metrics["recall"],
                "lr": lr,
                "batch_size": batch_size,
                "grad_accum": grad_accum,
                "device": str(device),
                "timestamp": datetime.now().isoformat(),
            }
            with open(os.path.join(save_dir, "training_config.json"), "w") as f:
                json.dump(config, f, indent=2)

            logger.info(f"    ✅ New best F1={best_val_f1:.4f} — saved to {save_dir}")
        else:
            epochs_no_improve += 1
            logger.info(
                f"    No improvement ({epochs_no_improve}/{patience}). "
                f"Best F1={best_val_f1:.4f} at epoch {best_epoch}"
            )

        if epochs_no_improve >= patience:
            logger.info(f"\n  ⏹️  Early stopping at epoch {epoch} (patience={patience})")
            break

    # ── 5. Test evaluation ───────────────────────────────────────────────
    logger.info("\n[4/4] Evaluating on test set...")

    # Reload best checkpoint
    if lora_applied:
        from peft import PeftModel
        base_model, _ = build_model(model_key, use_lora=False)
        model = PeftModel.from_pretrained(base_model, save_dir)
    else:
        model, _ = build_model(model_key, use_lora=False)
        model.load_state_dict(torch.load(os.path.join(save_dir, "model.pt"),
                                         map_location=device, weights_only=True))

    model = model.to(device)
    test_metrics = evaluate_epoch(model, test_loader, device)

    logger.info(
        f"\n  ── TEST RESULTS ({model_key}) ──\n"
        f"    Recall:    {test_metrics['recall']:.4f}  ← primary metric\n"
        f"    Precision: {test_metrics['precision']:.4f}\n"
        f"    F1:        {test_metrics['f1']:.4f}\n"
        f"    AUROC:     {test_metrics['auroc']:.4f}\n"
        f"    Accuracy:  {test_metrics['accuracy']:.4f}\n"
        f"    Loss:      {test_metrics['loss']:.4f}"
    )

    # Save results
    results = {
        "model": model_key,
        "use_lora": lora_applied,
        "checkpoint_dir": save_dir,
        "best_epoch": best_epoch,
        "test_metrics": test_metrics,
        "val_best_f1": best_val_f1,
        "training_history": history,
        "hyperparams": {
            "epochs": epochs,
            "lr": lr,
            "batch_size": batch_size,
            "grad_accum": grad_accum,
            "max_length": max_length,
            "patience": patience,
            "lora_r": LORA_R if lora_applied else None,
            "lora_alpha": LORA_ALPHA if lora_applied else None,
        },
        "timestamp": datetime.now().isoformat(),
    }

    results_path = os.path.join(LOGS_DIR, f"phase1_{model_key}_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\n  Results saved to: {results_path}")

    # Cleanup
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    return results


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune CodeT5 or GraphCodeBERT for binary vulnerability detection."
    )
    parser.add_argument(
        "--model", type=str, required=True,
        choices=["codet5", "graphcodebert"],
        help="Model to fine-tune",
    )
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--grad-accum", type=int, default=DEFAULT_GRAD_ACCUM)
    parser.add_argument("--patience", type=int, default=DEFAULT_PATIENCE)
    parser.add_argument(
        "--no-lora", action="store_true",
        help="Disable LoRA — use full fine-tuning instead",
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="Subsample dataset to this total size (stratified). "
             "Useful for faster training on consumer hardware.",
    )
    args = parser.parse_args()

    train(
        model_key=args.model,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        max_length=args.max_length,
        grad_accum=args.grad_accum,
        patience=args.patience,
        use_lora=not args.no_lora,
        max_samples=args.max_samples,
    )


if __name__ == "__main__":
    main()
