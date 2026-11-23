# Phase 1 — Binary Vulnerability Detection Results

**Task:** Classify source code functions as **Vulnerable** (1) or **Non-Vulnerable** (0).

**Dataset:** BigVul (20,000 stratified samples — 5% vulnerable, 95% non-vulnerable)

**Primary Metric:** Recall (catching vulnerabilities matters most)

---

## Models Trained

### 1. CodeT5 Binary Classifier (`codet5_results.json`)
- **What:** Salesforce/codet5-base encoder + mean pooling + binary classification head
- **Fine-tuning:** LoRA (rank=16, α=32) on attention projections `["q", "v"]`
- **Trainable params:** 591,362 / 110,199,940 (0.54%)
- **Epochs:** 5 (no early stopping triggered)
- **Training time:** ~67 min on Apple Silicon MPS
- **Checkpoint:** `models/saved/codet5_binary_best/`

### 2. GraphCodeBERT Binary Classifier (`graphcodebert_results.json`)
- **What:** Microsoft/graphcodebert-base (RoBERTa architecture) + sequence classification head
- **Fine-tuning:** LoRA (rank=16, α=32) on attention projections `["query", "value"]`
- **Epochs:** 5 (no early stopping triggered)
- **Training time:** ~59 min on Apple Silicon MPS
- **Checkpoint:** `models/saved/graphcodebert_binary_best/`

---

## Test Set Results (`comparison.json`)

| Metric | CodeT5 | GraphCodeBERT | Winner |
|--------|--------|---------------|--------|
| **Recall ★** | **0.5667** | 0.5533 | CodeT5 |
| Precision | **0.8586** | 0.8469 | CodeT5 |
| F1 | **0.6827** | 0.6694 | CodeT5 |
| AUROC | **0.9087** | 0.9062 | CodeT5 |
| Accuracy | **0.9737** | 0.9727 | CodeT5 |
| Loss ↓ | **0.1068** | 0.1174 | CodeT5 |

**🏆 Winner: CodeT5** — Won all 6 metrics. Higher Recall (primary metric): 0.5667 vs 0.5533.

Winner checkpoint copied to: `models/saved/phase1_winner/`

---

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Samples | 20,000 (stratified subsample) |
| Split | 70/15/15 (Train: 14,000 / Val: 3,000 / Test: 3,000) |
| Batch size | 8 (effective 32 with grad_accum=4) |
| Learning rate | 2e-4 |
| Optimizer | AdamW (weight_decay=0.01) |
| Scheduler | CosineAnnealingLR |
| Max token length | 256 |
