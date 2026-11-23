# Phase 1 — Detection Baseline: Binary Vulnerability Classification

**Project:** SecuraX — AI-Based Framework for Automated Source Code Vulnerability Detection  
**Date:** September 2026  
**Phase Goal:** Train and compare CodeT5 and GraphCodeBERT on binary vulnerable / non-vulnerable classification, select the winning backbone for Phase 2+.

---

## Prerequisites

No additional packages beyond `requirements.txt`. The following must already be set up:

- Python 3.9+ with virtual environment activated
- `pip install -r requirements.txt` (includes PyTorch, Transformers, PEFT, scikit-learn)
- BigVul dataset accessible via HuggingFace (`benjis/bigvul`)
- Base model weights downloaded locally (see [Local Model Setup](#local-model-setup))

---

## Local Model Setup

Due to SSL compatibility issues with Python 3.9 / LibreSSL on macOS, model weights are downloaded manually via `curl` and stored in `models/pretrained/`:

```bash
# CodeT5-base (~850MB)
mkdir -p models/pretrained/codet5-base
curl -L "https://huggingface.co/Salesforce/codet5-base/resolve/main/pytorch_model.bin" \
  -o models/pretrained/codet5-base/pytorch_model.bin
curl -L "https://huggingface.co/Salesforce/codet5-base/resolve/main/config.json" \
  -o models/pretrained/codet5-base/config.json

# GraphCodeBERT-base (~500MB)
mkdir -p models/pretrained/graphcodebert-base
curl -L "https://huggingface.co/microsoft/graphcodebert-base/resolve/main/pytorch_model.bin" \
  -o models/pretrained/graphcodebert-base/pytorch_model.bin
curl -L "https://huggingface.co/microsoft/graphcodebert-base/resolve/main/config.json" \
  -o models/pretrained/graphcodebert-base/config.json
```

The training script (`train_binary.py`) auto-detects local weights via `resolve_model_path()` and falls back to HuggingFace Hub if not found locally.

> **Note:** TensorFlow 2.20 causes a mutex deadlock (`[mutex.cc : 452] RAW: Lock blocking`) on macOS when loading transformers models. The training script sets `USE_TF=0` at startup to prevent this.

---

## Reproducing Training

### Step 1 — Train CodeT5

```bash
cd "Minor Project"
source .venv/bin/activate

PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_binary.py \
  --model codet5 --epochs 5 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 2 --max-length 256 --max-samples 20000
```

### Step 2 — Train GraphCodeBERT

```bash
PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_binary.py \
  --model graphcodebert --epochs 5 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 2 --max-length 256 --max-samples 20000
```

### Step 3 — Compare Both Models & Select Winner

```bash
python src/evaluation/evaluate_binary.py --compare
```

### Step 4 — Verify Inference

```bash
python src/evaluation/evaluate_binary.py --predict --model codet5 \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

**GPU notes:**
- **Apple Silicon (MPS):** Use `PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0` to prevent OOM. Use `--batch-size 8 --max-length 256`.
- **NVIDIA GPU (CUDA):** Can increase to `--batch-size 16 --max-length 512`. Remove the MPS env var.
- **CPU only:** Works but very slow. Not recommended for training.

---

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Dataset | BigVul (HuggingFace: `benjis/bigvul`) |
| Samples | 20,000 (stratified subsample) |
| Split | 70/15/15 (Train: 14,000 / Val: 3,000 / Test: 3,000) |
| Class ratio | 5.0% vulnerable (18.9:1 imbalance) |
| Max token length | 256 |
| Batch size | 8 (effective 32 with grad_accum=4) |
| Learning rate | 2e-4 |
| Optimizer | AdamW (weight_decay=0.01) |
| Scheduler | CosineAnnealingLR |
| LoRA rank (r) | 16 |
| LoRA alpha (α) | 32 |
| LoRA dropout | 0.1 |
| LoRA target modules | `["q", "v"]` (CodeT5) / `["query", "value"]` (GraphCodeBERT) |
| Early stopping | Patience = 2 (by val F1) |
| Epochs trained | 5 (both models) |
| Device | Apple Silicon MPS |

---

## Full Metrics Comparison

### Test Set Results

| Metric | CodeT5 | GraphCodeBERT | Winner |
|--------|--------|---------------|--------|
| **Recall ★** | **0.5667** | 0.5533 | CodeT5 |
| Precision | **0.8586** | 0.8469 | CodeT5 |
| F1 | **0.6827** | 0.6694 | CodeT5 |
| AUROC | **0.9087** | 0.9062 | CodeT5 |
| Accuracy | **0.9737** | 0.9727 | CodeT5 |
| Loss ↓ | **0.1068** | 0.1174 | CodeT5 |

**CodeT5 won all 6 metrics.** Both models were trained for the full 5 epochs without early stopping triggering.

### Training History — CodeT5

| Epoch | Train Loss | Val Loss | Val Recall | Val Precision | Val F1 | Val AUROC | Time |
|-------|-----------|----------|------------|---------------|--------|-----------|------|
| 1 | 0.1825 | 0.1255 | 0.5629 | 0.6028 | 0.5822 | 0.8922 | 13.6 min |
| 2 | 0.1001 | 0.1075 | 0.5563 | 0.7850 | 0.6512 | 0.9226 | 13.4 min |
| 3 | 0.0894 | 0.0972 | 0.5497 | 0.8058 | 0.6535 | 0.9342 | 13.4 min |
| 4 | 0.0825 | 0.1006 | 0.5762 | 0.7699 | 0.6591 | 0.9355 | 13.5 min |
| 5 | 0.0784 | 0.0973 | 0.5894 | 0.7607 | **0.6642** | 0.9362 | 13.7 min |

### Training History — GraphCodeBERT

| Epoch | Train Loss | Val Loss | Val Recall | Val Precision | Val F1 | Val AUROC | Time |
|-------|-----------|----------|------------|---------------|--------|-----------|------|
| 1 | 0.1568 | 0.1047 | 0.4901 | 0.9024 | 0.6352 | 0.9170 | 11.7 min |
| 2 | 0.1032 | 0.1024 | 0.5828 | 0.7521 | 0.6567 | 0.9214 | 11.8 min |
| 3 | 0.0903 | 0.0946 | 0.5629 | 0.8673 | 0.6827 | 0.9250 | 11.8 min |
| 4 | 0.0837 | 0.0999 | 0.5828 | 0.8302 | 0.6848 | 0.9259 | 11.8 min |
| 5 | 0.0767 | 0.1019 | 0.5894 | 0.8318 | **0.6899** | 0.9260 | 11.5 min |

**Total training time:** ~67 min (CodeT5) + ~59 min (GraphCodeBERT) = ~126 min on MPS.

---

## Backbone Selection Reasoning

**🏆 Winner: CodeT5** (Salesforce/codet5-base with LoRA adapters)

**Why CodeT5 won:**

1. **Higher Recall (primary metric):** 0.5667 vs 0.5533 — CodeT5 catches more vulnerabilities, which is the project's top priority (missing a vulnerability is worse than a false alarm).

2. **Higher Precision:** 0.8586 vs 0.8469 — CodeT5 also has fewer false positives.

3. **Better F1 score:** 0.6827 vs 0.6694 — better overall balance of Recall and Precision.

4. **Higher AUROC:** 0.9087 vs 0.9062 — better ranking ability across all thresholds.

5. **Lower loss:** 0.1068 vs 0.1174 — model is more confident in correct predictions.

6. **Clean sweep:** CodeT5 won on all 6 tracked metrics.

**Architecture notes:**
- CodeT5 uses a T5 encoder (~110M params) with mean-pooling + linear classifier head
- GraphCodeBERT uses a RoBERTa architecture (~125M params) with `AutoModelForSequenceClassification`
- Both use LoRA (rank=16, α=32) — only ~0.5% of parameters are trainable (~591K for CodeT5)

---

## Loading the Saved Model & Running Inference

```python
import torch
from src.data.dataset import get_tokenizer
from src.models.train_binary import CodeT5BinaryClassifier
from peft import PeftModel

# 1. Load tokenizer
tokenizer = get_tokenizer("codet5")

# 2. Load base model + LoRA adapter
base_model = CodeT5BinaryClassifier("Salesforce/codet5-base")
model = PeftModel.from_pretrained(base_model, "models/saved/phase1_winner")
model.eval()

# 3. Tokenize input
code = "int main() { char buf[10]; gets(buf); return 0; }"
inputs = tokenizer(code, max_length=256, padding="max_length",
                   truncation=True, return_tensors="pt")

# 4. Predict
with torch.no_grad():
    outputs = model(input_ids=inputs["input_ids"],
                    attention_mask=inputs["attention_mask"])
    probs = torch.softmax(outputs.logits, dim=-1)
    pred = probs.argmax(dim=-1).item()

label = "VULNERABLE" if pred == 1 else "NON-VULNERABLE"
confidence = probs[0, pred].item()
print(f"Prediction: {label} ({confidence:.2%})")
```

Or use the CLI shortcut:

```bash
python src/evaluation/evaluate_binary.py --predict --model codet5 \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

---

## Output Files

| File | Description |
|------|-------------|
| `models/saved/codet5_binary_best/` | CodeT5 LoRA checkpoint (best val F1) |
| `models/saved/graphcodebert_binary_best/` | GraphCodeBERT LoRA checkpoint (best val F1) |
| `models/saved/phase1_winner/` | Copy of the winning model (CodeT5) |
| `logs/train_codet5_binary.log` | CodeT5 training log |
| `logs/train_graphcodebert_binary.log` | GraphCodeBERT training log |
| `logs/phase1_codet5_results.json` | CodeT5 metrics + training history |
| `logs/phase1_graphcodebert_results.json` | GraphCodeBERT metrics + training history |
| `logs/phase1_comparison.json` | Side-by-side comparison + winner metadata |

---

## Known Limitations

1. **Class imbalance (18.9:1) not yet handled.** The dataset is 95% non-vulnerable / 5% vulnerable. No class weighting, oversampling, or focal loss was applied. This likely hurts Recall — the model is biased toward predicting "non-vulnerable" for borderline cases. Addressing this in Phase 2+ (e.g., weighted CrossEntropyLoss, SMOTE on embeddings) should improve Recall significantly.

2. **Dataset subsampled to 20K for training speed.** The full BigVul dataset has 217K samples. Training on the full dataset would likely improve all metrics, at the cost of ~10× longer training time.

3. **Max token length = 256 truncates longer functions.** The median function in BigVul has 14 LOC, but the mean is 30.7 LOC with some up to 6,820 LOC. At 256 tokens, longer functions are truncated. Increasing to 512 would capture more context but requires more GPU memory.

4. **Binary classification only.** This phase only detects "vulnerable vs. non-vulnerable." CWE classification (Phase 2) and severity scoring (Phase 3) will extend this.

5. **Prediction demo returns NON-VULNERABLE for `gets()`.** The classic buffer overflow via `gets()` was predicted as non-vulnerable with 96% confidence. This illustrates the Recall limitation — the model has high precision (few false positives) but misses some real vulnerabilities, especially short snippets without surrounding context.

6. **LoRA only fine-tunes attention projections.** Only `q` and `v` matrices are adapted (0.54% of parameters). Full fine-tuning or targeting more modules may improve performance.

---

## What's Next — Phase 2

Phase 2 will focus on **CWE Multi-Class Classification**:
- Extend the binary classifier to predict CWE-ids (90 classes)
- Address class imbalance with weighted loss or oversampling
- Use the CodeT5 backbone selected in this phase
- Evaluate with macro/micro F1, top-k accuracy
