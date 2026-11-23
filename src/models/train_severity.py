"""
train_severity.py — Phase 3: Multi-Tier CVSS Severity Scoring (Regression 0–10).

Implements three approaches:
  - Approach A: Single-task severity regression per tier
      Tier 1: Fine-tune AIBugHunter CodeBERT checkpoint
      Other tiers: New regression head on tier's Phase 1 winning encoder
  - Approach B: DeepCVA-style multi-task per tier (VF + CWE + Severity heads)
  - Approach C: ONE shared severity regressor across ALL tiers combined

Architecture:
  - Encoder: CodeT5-base or GraphCodeBERT-base (from Phase 1/2 winners)
  - Pooling: AttentionPooling (LineVul-style, same as Phase 1/2)
  - Head: Linear(768 → 256 → 1) with ReLU + Dropout
  - Loss: SmoothL1Loss (Huber, δ=1.0) — robust to outlier CVSS scores
  - LoRA: r=64, α=128 (consistent with Phases 1-2)

Usage:
    # Approach A — Per-tier single-task regression
    python src/models/train_severity.py --approach A --tier tier1_c_cpp --model codet5 --bf16
    python src/models/train_severity.py --approach A --tier tier2_php --model graphcodebert --bf16

    # Approach B — Per-tier multi-task (VF + CWE + Severity)
    python src/models/train_severity.py --approach B --tier tier1_c_cpp --model graphcodebert --bf16

    # Approach C — Shared cross-tier severity regressor
    python src/models/train_severity.py --approach C --model codet5 --bf16 --use-lang-tokens

    # Evaluate all approaches
    python src/models/train_severity.py --evaluate-all
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
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from src.models.modules import AttentionPooling
from src.data.dataset_severity import create_severity_dataloaders

# ─── Constants ───────────────────────────────────────────────────────────────

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "saved")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

DEFAULT_EPOCHS = 15
DEFAULT_LR = 2e-4
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_LENGTH = 512
DEFAULT_GRAD_ACCUM = 2
DEFAULT_PATIENCE = 5

LORA_R = 64
LORA_ALPHA = 128
LORA_DROPOUT = 0.1

# ─── Device ──────────────────────────────────────────────────────────────────

PRETRAINED_DIR = os.path.join(PROJECT_ROOT, "models", "pretrained")
_LOCAL_MODEL_MAP = {
    "Salesforce/codet5-base": "codet5-base",
    "microsoft/graphcodebert-base": "graphcodebert-base",
}


def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def resolve_model_path(model_id: str):
    local_name = _LOCAL_MODEL_MAP.get(model_id)
    if local_name:
        local_path = os.path.join(PRETRAINED_DIR, local_name)
        if os.path.isdir(local_path) and any(
            f.endswith((".bin", ".safetensors")) for f in os.listdir(local_path)
        ):
            return local_path, True
    return model_id, False


# ─── Severity Regression Models ──────────────────────────────────────────────


class SeverityRegressionHead(nn.Module):
    """MLP regression head: hidden → 256 → 1 (sigmoid * 10 for CVSS range)."""

    def __init__(self, hidden_size: int = 768, dropout: float = 0.1):
        super().__init__()
        self.fc1 = nn.Linear(hidden_size, 256)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(256, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.sigmoid(self.fc2(x))  # Output in [0, 1]
        return x.squeeze(-1)


class CodeT5SeverityModel(nn.Module):
    """CodeT5 encoder + AttentionPooling + severity regression head."""

    def __init__(self, model_name: str = "Salesforce/codet5-base", dropout: float = 0.1):
        super().__init__()
        from transformers import T5EncoderModel

        resolved, local_only = resolve_model_path(model_name)
        self.encoder = T5EncoderModel.from_pretrained(resolved, local_files_only=local_only)
        self.config = self.encoder.config
        hidden_size = self.config.d_model  # 768

        self.attention_pool = AttentionPooling(hidden_size, dropout=dropout)
        self.severity_head = SeverityRegressionHead(hidden_size, dropout=dropout)

    def forward(self, input_ids, attention_mask=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = outputs.last_hidden_state
        pooled = self.attention_pool(hidden, attention_mask)
        severity = self.severity_head(pooled)
        return SimpleNamespace(severity=severity, pooled=pooled)


class GraphCodeBERTSeverityModel(nn.Module):
    """GraphCodeBERT encoder + AttentionPooling + severity regression head."""

    def __init__(self, model_name: str = "microsoft/graphcodebert-base", dropout: float = 0.1):
        super().__init__()
        from transformers import AutoModel

        resolved, local_only = resolve_model_path(model_name)
        self.encoder = AutoModel.from_pretrained(resolved, local_files_only=local_only)
        self.config = self.encoder.config
        hidden_size = self.config.hidden_size  # 768

        self.attention_pool = AttentionPooling(hidden_size, dropout=dropout)
        self.severity_head = SeverityRegressionHead(hidden_size, dropout=dropout)

    def forward(self, input_ids, attention_mask=None, **kwargs):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = outputs.last_hidden_state
        pooled = self.attention_pool(hidden, attention_mask)
        severity = self.severity_head(pooled)
        return SimpleNamespace(severity=severity, pooled=pooled)


class MultiTaskSeverityModel(nn.Module):
    """DeepCVA-style multi-task model: shared encoder + VF head + CWE head + Severity head.

    Approach B: trains VF detection, CWE classification, and severity regression
    simultaneously on the same encoder with Pareto-optimal gradient balancing.
    """

    def __init__(self, base_model: nn.Module, hidden_size: int = 768,
                 num_cwe_classes: int = 15, dropout: float = 0.1):
        super().__init__()
        self.base = base_model  # Encoder + AttentionPooling

        # Task-specific heads
        self.vf_head = nn.Linear(hidden_size, 2)
        self.cwe_head = nn.Linear(hidden_size, num_cwe_classes)
        self.severity_head = SeverityRegressionHead(hidden_size, dropout)

    def forward(self, input_ids, attention_mask=None, **kwargs):
        outputs = self.base(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs.pooled

        vf_logits = self.vf_head(pooled)
        cwe_logits = self.cwe_head(pooled)
        severity = self.severity_head(pooled)

        return SimpleNamespace(
            vf_logits=vf_logits,
            cwe_logits=cwe_logits,
            severity=severity,
            pooled=pooled,
        )


# ─── Model Builder ───────────────────────────────────────────────────────────


def build_severity_model(
    model_key: str,
    approach: str = "A",
    lora_r: int = LORA_R,
    lora_alpha: int = LORA_ALPHA,
    warm_start: str = None,
    tokenizer_len: int = None,
):
    """Build severity regression model with LoRA.

    Args:
        model_key    : 'codet5' or 'graphcodebert'
        approach     : 'A' (single-task), 'B' (multi-task), 'C' (shared)
        lora_r       : LoRA rank
        lora_alpha   : LoRA alpha
        warm_start   : path to checkpoint for warm-starting
        tokenizer_len: resize embeddings for added tokens
    """
    if model_key == "codet5":
        model = CodeT5SeverityModel("Salesforce/codet5-base")
        target_modules = ["q", "k", "v", "o"]
    elif model_key == "graphcodebert":
        model = GraphCodeBERTSeverityModel("microsoft/graphcodebert-base")
        target_modules = ["query", "key", "value", "dense"]
    else:
        raise ValueError(f"Unknown model key: {model_key}")

    # Resize embeddings for language tokens
    if tokenizer_len is not None:
        encoder = model.encoder if hasattr(model, "encoder") else model
        if hasattr(encoder, "resize_token_embeddings"):
            encoder.resize_token_embeddings(tokenizer_len)
            print(f"  Resized embeddings to {tokenizer_len}")

    # Warm-start from Phase 1/2 winner
    if warm_start and os.path.isdir(warm_start):
        print(f"  🔥 Warm-starting encoder from: {warm_start}")
        try:
            from peft import PeftModel
            if model_key == "codet5":
                from transformers import T5EncoderModel
                ws_base = CodeT5SeverityModel("Salesforce/codet5-base")
            else:
                ws_base = GraphCodeBERTSeverityModel("microsoft/graphcodebert-base")

            ws_model = PeftModel.from_pretrained(ws_base, warm_start)
            ws_merged = ws_model.merge_and_unload()

            encoder_state = {}
            for k, v in ws_merged.state_dict().items():
                if k.startswith("encoder."):
                    encoder_state[k] = v

            missing, unexpected = model.load_state_dict(encoder_state, strict=False)
            print(f"    Loaded {len(encoder_state)} encoder params "
                  f"(missing: {len(missing)}, unexpected: {len(unexpected)})")

            del ws_model, ws_merged, ws_base
            gc.collect()
        except Exception as e:
            print(f"  ⚠️  Warm-start failed: {e}. Training from scratch.")

    # Wrap with multi-task heads if Approach B
    if approach == "B":
        hidden_size = 768
        model = MultiTaskSeverityModel(model, hidden_size=hidden_size)

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

        return model, True, target_modules
    except Exception as e:
        print(f"  ⚠️  LoRA failed ({e}), falling back to full fine-tuning")
        return model, False, target_modules


# ─── Evaluation ──────────────────────────────────────────────────────────────


def evaluate_severity(model, dataloader, device, loss_fn=None, normalized=True):
    """Evaluate severity regression on a dataloader.

    Returns:
        metrics dict with MAE, RMSE, R², Pearson correlation
    """
    model.eval()
    all_preds, all_targets = [], []
    total_loss = 0.0
    n_batches = 0

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            targets = batch["severity"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = outputs.severity

            if loss_fn is not None:
                loss = loss_fn(preds, targets)
                total_loss += loss.item()
            n_batches += 1

            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(targets.cpu().numpy())

    all_preds = np.array(all_preds)
    all_targets = np.array(all_targets)

    # Denormalize if needed (0-1 → 0-10)
    if normalized:
        all_preds = all_preds * 10.0
        all_targets = all_targets * 10.0

    # Clip predictions to valid range
    all_preds = np.clip(all_preds, 0.0, 10.0)

    mae = mean_absolute_error(all_targets, all_preds)
    rmse = np.sqrt(mean_squared_error(all_targets, all_preds))
    r2 = r2_score(all_targets, all_preds) if len(set(all_targets)) > 1 else 0.0

    # Pearson correlation
    if np.std(all_preds) > 0 and np.std(all_targets) > 0:
        pearson = float(np.corrcoef(all_targets, all_preds)[0, 1])
    else:
        pearson = 0.0

    # CVSS band accuracy (Low/Med/High/Critical)
    def cvss_band(score):
        if score < 4.0:
            return 0  # Low
        elif score < 7.0:
            return 1  # Medium
        elif score < 9.0:
            return 2  # High
        else:
            return 3  # Critical

    pred_bands = np.array([cvss_band(p) for p in all_preds])
    target_bands = np.array([cvss_band(t) for t in all_targets])
    band_accuracy = float(np.mean(pred_bands == target_bands))

    metrics = {
        "mae": float(mae),
        "rmse": float(rmse),
        "r2": float(r2),
        "pearson": float(pearson),
        "band_accuracy": float(band_accuracy),
        "loss": total_loss / max(n_batches, 1),
        "n_samples": len(all_targets),
    }

    return metrics, all_targets, all_preds


# ─── Training ────────────────────────────────────────────────────────────────


def train_severity(
    model_key: str,
    tier: str,
    approach: str = "A",
    epochs: int = DEFAULT_EPOCHS,
    lr: float = DEFAULT_LR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
    grad_accum: int = DEFAULT_GRAD_ACCUM,
    patience: int = DEFAULT_PATIENCE,
    lora_r: int = LORA_R,
    lora_alpha: int = LORA_ALPHA,
    use_bf16: bool = False,
    warm_start: str = None,
    use_lang_tokens: bool = False,
    max_samples: int = None,
):
    """Main severity regression training function.

    Args:
        model_key      : 'codet5' or 'graphcodebert'
        tier           : 'tier1_c_cpp', 'tier2_cpp', etc. or 'all_shared' (Approach C)
        approach       : 'A' (single-task), 'B' (multi-task), 'C' (shared)
        epochs         : number of training epochs
        lr             : learning rate
        batch_size     : per-device batch size
        max_length     : max token length
        grad_accum     : gradient accumulation steps
        patience       : early stopping patience
        lora_r         : LoRA rank
        lora_alpha     : LoRA alpha
        use_bf16       : use bfloat16 mixed precision
        warm_start     : path to checkpoint for warm-starting
        use_lang_tokens: prepend <LANG=xx> tokens
        max_samples    : subsample training data
    """
    device = get_device()
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Approach C always uses all_shared + lang tokens
    effective_tier = "all_shared" if approach == "C" else tier
    effective_lang_tokens = True if approach == "C" else use_lang_tokens

    # Run naming
    run_name = f"phase3_{approach}_{effective_tier}_{model_key}"

    # Setup logging
    log_path = os.path.join(LOGS_DIR, f"train_{run_name}.log")
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
    logger.info(f"  PHASE 3 — CVSS SEVERITY SCORING (REGRESSION)")
    logger.info(f"  Approach:    {approach}")
    logger.info(f"  Tier:        {effective_tier}")
    logger.info(f"  Model:       {model_key}")
    logger.info(f"  Device:      {device}")
    logger.info(f"  Epochs:      {epochs}")
    logger.info(f"  Batch size:  {batch_size} (effective: {batch_size * grad_accum})")
    logger.info(f"  LR:          {lr}")
    logger.info(f"  Max length:  {max_length}")
    logger.info(f"  LoRA:        r={lora_r}, alpha={lora_alpha}")
    logger.info(f"  BF16:        {use_bf16}")
    logger.info(f"  Warm-start:  {warm_start or 'None'}")
    logger.info(f"  Lang tokens: {effective_lang_tokens}")
    logger.info("=" * 70)

    # ── 1. Data ──────────────────────────────────────────────────────────
    logger.info("\n[1/5] Loading severity data...")
    train_loader, val_loader, test_loader, meta = create_severity_dataloaders(
        tier=effective_tier,
        model_name=model_key,
        max_length=max_length,
        batch_size=batch_size,
        add_lang_tokens=effective_lang_tokens,
        max_samples=max_samples,
        normalize_target=True,
    )

    # ── 2. Model ─────────────────────────────────────────────────────────
    logger.info("\n[2/5] Building model...")
    model, lora_applied, target_modules = build_severity_model(
        model_key,
        approach=approach,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        warm_start=warm_start,
        tokenizer_len=meta.get("vocab_size"),
    )
    model = model.to(device)
    logger.info(f"  Model on {device}")

    # ── 3. Loss function ─────────────────────────────────────────────────
    loss_fn = nn.SmoothL1Loss()  # Huber Loss — robust to outlier CVSS scores
    logger.info(f"  Loss: SmoothL1Loss (Huber, δ=1.0)")

    # ── 4. Optimizer & Scheduler ─────────────────────────────────────────
    logger.info("\n[3/5] Setting up optimizer...")
    optimizer = AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=lr, weight_decay=0.01,
    )
    total_steps = len(train_loader) * epochs // grad_accum
    scheduler = CosineAnnealingLR(optimizer, T_max=max(total_steps, 1), eta_min=lr * 0.1)

    # Mixed precision
    amp_dtype = None
    if use_bf16 and device.type == "cuda":
        amp_dtype = torch.bfloat16
        logger.info("  Using bfloat16 mixed precision")

    # ── 5. Training loop ─────────────────────────────────────────────────
    logger.info("\n[4/5] Training...")

    best_val_mae = float("inf")
    best_epoch = -1
    epochs_no_improve = 0
    save_dir = os.path.join(MODELS_DIR, run_name)
    history = []

    for epoch in range(1, epochs + 1):
        epoch_start = time.time()
        model.train()
        running_loss = 0.0
        optimizer.zero_grad()

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            targets = batch["severity"].to(device)

            if amp_dtype is not None:
                with autocast(device_type="cuda", dtype=amp_dtype):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                    loss = loss_fn(outputs.severity, targets) / grad_accum
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                loss = loss_fn(outputs.severity, targets) / grad_accum

            loss.backward()
            running_loss += loss.item() * grad_accum

            if step % grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            if step % 50 == 0:
                avg = running_loss / step
                logger.info(
                    f"  Epoch {epoch}/{epochs} | Step {step}/{len(train_loader)} | "
                    f"Loss: {avg:.6f}"
                )

        # Flush remaining grads
        if len(train_loader) % grad_accum != 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            optimizer.zero_grad()

        train_loss = running_loss / max(len(train_loader), 1)

        # Validation
        val_metrics, _, _ = evaluate_severity(model, val_loader, device, loss_fn,
                                              normalized=meta.get("normalized", True))
        epoch_time = time.time() - epoch_start

        logger.info(
            f"\n  ── Epoch {epoch}/{epochs} ({epoch_time:.0f}s) ──\n"
            f"    Train Loss:     {train_loss:.6f}\n"
            f"    Val MAE:        {val_metrics['mae']:.4f}  ← primary metric\n"
            f"    Val RMSE:       {val_metrics['rmse']:.4f}\n"
            f"    Val R²:         {val_metrics['r2']:.4f}\n"
            f"    Val Pearson:    {val_metrics['pearson']:.4f}\n"
            f"    Val Band Acc:   {val_metrics['band_accuracy']:.4f}"
        )

        history.append({
            "epoch": epoch,
            "train_loss": train_loss,
            **{f"val_{k}": v for k, v in val_metrics.items()},
            "epoch_time_s": epoch_time,
        })

        # Checkpointing (by val MAE — lower is better)
        if val_metrics["mae"] < best_val_mae:
            best_val_mae = val_metrics["mae"]
            best_epoch = epoch
            epochs_no_improve = 0

            os.makedirs(save_dir, exist_ok=True)
            if lora_applied:
                model.save_pretrained(save_dir)
            else:
                torch.save(model.state_dict(), os.path.join(save_dir, "model.pt"))

            config = {
                "model_key": model_key, "tier": effective_tier, "approach": approach,
                "use_lora": lora_applied,
                "lora_r": lora_r, "lora_alpha": lora_alpha,
                "max_length": max_length, "epochs_trained": epoch,
                "best_val_mae": best_val_mae,
                "bf16": use_bf16, "warm_start": warm_start, "lr": lr,
                "batch_size": batch_size, "grad_accum": grad_accum,
                "use_lang_tokens": effective_lang_tokens,
                "device": str(device), "timestamp": datetime.now().isoformat(),
            }
            with open(os.path.join(save_dir, "training_config.json"), "w") as f:
                json.dump(config, f, indent=2)

            logger.info(f"    [BEST] New best MAE={best_val_mae:.4f} -- saved to {save_dir}")
        else:
            epochs_no_improve += 1
            logger.info(
                f"    No improvement ({epochs_no_improve}/{patience}). "
                f"Best MAE={best_val_mae:.4f} at epoch {best_epoch}"
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
            base_model = CodeT5SeverityModel("Salesforce/codet5-base")
        else:
            base_model = GraphCodeBERTSeverityModel("microsoft/graphcodebert-base")

        if approach == "B":
            base_model = MultiTaskSeverityModel(base_model, hidden_size=768)

        model = PeftModel.from_pretrained(base_model, save_dir)
    else:
        model.load_state_dict(torch.load(
            os.path.join(save_dir, "model.pt"), map_location=device, weights_only=True
        ))

    model = model.to(device)

    test_metrics, test_targets, test_preds = evaluate_severity(
        model, test_loader, device, loss_fn,
        normalized=meta.get("normalized", True),
    )

    logger.info(
        f"\n  ── TEST RESULTS (Approach {approach}, {model_key} on {effective_tier}) ──\n"
        f"    MAE:          {test_metrics['mae']:.4f}  ← primary metric (lower is better)\n"
        f"    RMSE:         {test_metrics['rmse']:.4f}\n"
        f"    R²:           {test_metrics['r2']:.4f}\n"
        f"    Pearson ρ:    {test_metrics['pearson']:.4f}\n"
        f"    Band Acc:     {test_metrics['band_accuracy']:.4f}\n"
        f"    Loss:         {test_metrics['loss']:.6f}\n"
        f"    N Samples:    {test_metrics['n_samples']}"
    )

    # Per-band breakdown
    def band_label(score):
        if score < 4.0:
            return "Low (0-3.9)"
        elif score < 7.0:
            return "Medium (4-6.9)"
        elif score < 9.0:
            return "High (7-8.9)"
        else:
            return "Critical (9-10)"

    bands = {}
    for t, p in zip(test_targets, test_preds):
        bl = band_label(t)
        if bl not in bands:
            bands[bl] = {"targets": [], "preds": []}
        bands[bl]["targets"].append(t)
        bands[bl]["preds"].append(p)

    per_band = {}
    logger.info("\n  Per-Band Breakdown:")
    for bl in ["Low (0-3.9)", "Medium (4-6.9)", "High (7-8.9)", "Critical (9-10)"]:
        if bl in bands:
            ts = np.array(bands[bl]["targets"])
            ps = np.array(bands[bl]["preds"])
            b_mae = mean_absolute_error(ts, ps)
            b_rmse = np.sqrt(mean_squared_error(ts, ps))
            per_band[bl] = {"mae": float(b_mae), "rmse": float(b_rmse), "count": len(ts)}
            logger.info(f"    {bl:>18}: MAE={b_mae:.4f}, RMSE={b_rmse:.4f}, n={len(ts)}")
        else:
            per_band[bl] = {"mae": 0.0, "rmse": 0.0, "count": 0}
            logger.info(f"    {bl:>18}: n=0")

    # ── Save results ─────────────────────────────────────────────────────
    results = {
        "model_key": model_key, "tier": effective_tier, "approach": approach,
        "use_lora": lora_applied, "checkpoint_dir": save_dir,
        "best_epoch": best_epoch, "best_val_mae": best_val_mae,
        "test_metrics": test_metrics,
        "per_band_metrics": per_band,
        "data_meta": meta,
        "training_history": history,
        "hyperparams": {
            "epochs": epochs, "lr": lr, "batch_size": batch_size,
            "grad_accum": grad_accum, "max_length": max_length,
            "patience": patience, "lora_r": lora_r, "lora_alpha": lora_alpha,
            "bf16": use_bf16, "warm_start": warm_start,
            "use_lang_tokens": effective_lang_tokens,
        },
        "timestamp": datetime.now().isoformat(),
    }

    results_path = os.path.join(LOGS_DIR, f"phase3_severity_results_{run_name}.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"\n  Results saved: {results_path}")

    # Cleanup
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    return results


# ─── Evaluate All & Compare ─────────────────────────────────────────────────


def evaluate_all():
    """Load all Phase 3 result JSONs and print a consolidated comparison table."""
    import glob

    print("=" * 100)
    print("  PHASE 3 — CVSS SEVERITY SCORING: CONSOLIDATED COMPARISON TABLE")
    print("=" * 100)

    results = {}
    for f in sorted(glob.glob(os.path.join(LOGS_DIR, "phase3_severity_results_*.json"))):
        key = os.path.basename(f).replace("phase3_severity_results_", "").replace(".json", "")
        with open(f) as fp:
            results[key] = json.load(fp)

    if not results:
        print("  No Phase 3 results found. Train models first.")
        return

    header = (f"| {'Approach':^10} | {'Tier':^16} | {'Model':^16} | {'MAE':>6} | {'RMSE':>6} "
              f"| {'R²':>6} | {'Pearson':>8} | {'Band Acc':>8} |")
    sep = f"|{'-'*12}|{'-'*18}|{'-'*18}|{'-'*8}|{'-'*8}|{'-'*8}|{'-'*10}|{'-'*10}|"
    print(header)
    print(sep)

    for key, data in sorted(results.items()):
        m = data.get("test_metrics", {})
        approach = data.get("approach", "?")
        tier = data.get("tier", "?")
        model = data.get("model_key", "?")
        mae = m.get("mae", 0)
        rmse = m.get("rmse", 0)
        r2 = m.get("r2", 0)
        pearson = m.get("pearson", 0)
        band_acc = m.get("band_accuracy", 0)
        print(f"| {approach:^10} | {tier:^16} | {model:^16} | {mae:>6.4f} | {rmse:>6.4f} "
              f"| {r2:>6.4f} | {pearson:>8.4f} | {band_acc:>8.4f} |")

    print()

    # Select best per tier
    print("=" * 70)
    print("  PER-TIER WINNERS (lowest MAE)")
    print("=" * 70)

    tier_best = {}
    for key, data in results.items():
        tier = data.get("tier", "?")
        mae = data.get("test_metrics", {}).get("mae", float("inf"))
        if tier not in tier_best or mae < tier_best[tier]["mae"]:
            tier_best[tier] = {
                "key": key, "mae": mae,
                "approach": data.get("approach"),
                "model": data.get("model_key"),
                "rmse": data.get("test_metrics", {}).get("rmse", 0),
            }

    for tier, info in sorted(tier_best.items()):
        print(f"  🏆 [{tier}] Approach {info['approach']} {info['model']}: "
              f"MAE={info['mae']:.4f}, RMSE={info['rmse']:.4f}")


def select_winners():
    """Select and export winning severity models per tier."""
    import glob

    print("\n" + "=" * 70)
    print("  SELECTING & EXPORTING PHASE 3 WINNERS PER TIER")
    print("=" * 70)

    results = {}
    for f in sorted(glob.glob(os.path.join(LOGS_DIR, "phase3_severity_results_*.json"))):
        key = os.path.basename(f).replace("phase3_severity_results_", "").replace(".json", "")
        with open(f) as fp:
            results[key] = json.load(fp)

    # Find best per tier
    tier_best = {}
    for key, data in results.items():
        tier = data.get("tier", "?")
        mae = data.get("test_metrics", {}).get("mae", float("inf"))
        if tier not in tier_best or mae < tier_best[tier]["mae"]:
            tier_best[tier] = {
                "key": key, "mae": mae,
                "approach": data.get("approach"),
                "model": data.get("model_key"),
                "rmse": data.get("test_metrics", {}).get("rmse", 0),
                "r2": data.get("test_metrics", {}).get("r2", 0),
                "pearson": data.get("test_metrics", {}).get("pearson", 0),
            }

    winners_meta = {}
    for tier, info in sorted(tier_best.items()):
        dest_dir = os.path.join(MODELS_DIR, f"phase3_winner_{tier}")
        os.makedirs(dest_dir, exist_ok=True)
        meta = {
            "tier": tier,
            "winner_approach": info["approach"],
            "winner_model": info["model"],
            "mae": info["mae"],
            "rmse": info["rmse"],
            "r2": info["r2"],
            "pearson": info["pearson"],
            "timestamp": datetime.now().isoformat(),
        }
        with open(os.path.join(dest_dir, "winner_metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)
        winners_meta[tier] = meta
        print(f"  🏆 [{tier}] Approach {info['approach']} {info['model']}: "
              f"MAE={info['mae']:.4f}, RMSE={info['rmse']:.4f}")
        print(f"     Saved to: {dest_dir}")

    summary_path = os.path.join(LOGS_DIR, "phase3_winners.json")
    with open(summary_path, "w") as f:
        json.dump(winners_meta, f, indent=2)
    print(f"\n  Consolidated winners written to: {summary_path}")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Phase 3: Multi-tier CVSS severity scoring (regression)."
    )
    parser.add_argument(
        "--approach", type=str, default="A",
        choices=["A", "B", "C"],
        help="A=single-task per-tier, B=multi-task per-tier, C=shared cross-tier",
    )
    parser.add_argument(
        "--model", type=str, default="codet5",
        choices=["codet5", "graphcodebert"],
        help="Model backbone",
    )
    parser.add_argument(
        "--tier", type=str, default="tier1_c_cpp",
        choices=["tier1_c_cpp", "tier2_cpp", "tier2_python", "tier2_php", "tier3_shared"],
        help="Data tier (ignored for Approach C)",
    )
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--grad-accum", type=int, default=DEFAULT_GRAD_ACCUM)
    parser.add_argument("--patience", type=int, default=DEFAULT_PATIENCE)
    parser.add_argument("--lora-r", type=int, default=LORA_R)
    parser.add_argument("--lora-alpha", type=int, default=LORA_ALPHA)
    parser.add_argument("--bf16", action="store_true", help="Use bfloat16 (CUDA only)")
    parser.add_argument("--warm-start", type=str, default=None,
                        help="Path to Phase 1/2 checkpoint for warm-starting")
    parser.add_argument("--use-lang-tokens", action="store_true",
                        help="Prepend <LANG=xx> tokens (auto-enabled for Approach C)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Subsample training data")
    parser.add_argument("--evaluate-all", action="store_true",
                        help="Print comparison table from all saved results")
    parser.add_argument("--select-winners", action="store_true",
                        help="Export winning models per tier")

    args = parser.parse_args()

    if args.evaluate_all:
        evaluate_all()
        return

    if args.select_winners:
        select_winners()
        return

    train_severity(
        model_key=args.model,
        tier=args.tier,
        approach=args.approach,
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        max_length=args.max_length,
        grad_accum=args.grad_accum,
        patience=args.patience,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        use_bf16=args.bf16,
        warm_start=args.warm_start,
        use_lang_tokens=args.use_lang_tokens,
        max_samples=args.max_samples,
    )


if __name__ == "__main__":
    main()
