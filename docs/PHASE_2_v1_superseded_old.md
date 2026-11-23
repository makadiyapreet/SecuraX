# Phase 2 — Multi-Class CWE Classification

**Project:** SecuraX — AI-Based Framework for Automated Source Code Vulnerability Detection  
**Date:** September 2026  
**Phase Goal:** Train a multi-class CWE-id classifier on top of the CodeT5 backbone (Phase 1 winner), handling the severe class imbalance across 84 CWE types.

---

## Prerequisites

No additional packages beyond `requirements.txt`. From Phase 1:

- Python 3.9+ with virtual environment activated
- `pip install -r requirements.txt`
- BigVul dataset accessible via HuggingFace (`benjis/bigvul`)
- CodeT5-base weights in `models/pretrained/codet5-base/` (see Phase 1 local setup)

---

## Class Imbalance Analysis & Strategy

### The Problem

BigVul contains **8,760 vulnerable samples** with valid CWE IDs across **84 unique CWE classes**. The distribution is severely imbalanced:

| Bucket | # Classes | Cumulative % of Data |
|--------|-----------|---------------------|
| ≥ 100 samples | 14 classes | ~82% |
| 50–99 samples | 9 classes | ~8% |
| 10–49 samples | 21 classes | ~8% |
| < 10 samples | 40 classes | ~2% |

The top class (CWE-119) has 2,139 samples (24.4%), while 27 classes have fewer than 5 samples each.

### Strategy Chosen: Bucketing + Weighted Loss

**Two-pronged approach:**

1. **Rare-class bucketing:** CWE classes with < 50 samples are merged into an "Other" class.
   - 84 → **24 classes** (23 individual CWEs + "Other")
   - Ensures ≥ 35 training samples per class after 70/15/15 split
   - "Other" still flags the code as vulnerable with an unspecified CWE type

2. **Inverse-frequency weighted CrossEntropyLoss:**
   - Weight = `total_samples / (num_classes × class_count)`
   - Clamped at 10× to prevent extreme upweighting of rare classes
   - Normalized so mean weight = 1.0

**Why not focal loss?** Focal loss adds an extra hyperparameter (γ) and is better suited for binary detection than multi-class. Weighted CE is simpler, well-tested, and sufficient for our 24-class problem. The bucketing already eliminates the extreme long tail.

**Why not full Phase 1 LoRA reuse?** Phase 1 LoRA adapters were tuned for binary "vulnerable vs. non-vulnerable" detection — a fundamentally different task. CWE classification needs to distinguish *between* vulnerability types, so fresh LoRA adapters trained from scratch on the base encoder avoid negative transfer.

---

## Reproducing Training

### Step 1 — Train CWE Classifier

```bash
cd "Minor Project"
source .venv/bin/activate

PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_cwe.py \
  --epochs 10 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 3 --max-length 256
```

### Step 2 — Evaluate

```bash
python src/evaluation/evaluate_cwe.py --evaluate
```

### Step 3 — Test Prediction

```bash
python src/evaluation/evaluate_cwe.py --predict \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

**GPU notes (same as Phase 1):**
- **Apple Silicon (MPS):** `PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0`, batch-size 8
- **NVIDIA GPU (CUDA):** Can increase batch-size to 16
- **CPU only:** Works but slow, not recommended

---

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Dataset | BigVul — 8,760 vulnerable samples with valid CWE IDs |
| Split | 70/15/15 stratified by CWE class |
| Train / Val / Test | 6,132 / 1,314 / 1,314 |
| Num classes | 24 (23 CWEs with ≥50 samples + "Other" bucket) |
| Max token length | 256 |
| Batch size | 8 (effective 32 with grad_accum=4) |
| Learning rate | 2e-4 |
| Optimizer | AdamW (weight_decay=0.01) |
| Scheduler | CosineAnnealingLR |
| LoRA rank (r) | 16 |
| LoRA alpha (α) | 32 |
| LoRA dropout | 0.1 |
| LoRA target modules | `["q", "v"]` (T5 attention) |
| Early stopping | Patience = 3 (by val macro-F1) |
| Epochs trained | 10 (best at epoch 10) |
| Class weight clamping | 10× max |
| Device | Apple Silicon MPS |

---

## CWE Label Mapping

24 classes (sorted alphabetically, "Other" last):

| Index | CWE | Description | Train Samples |
|-------|-----|-------------|---------------|
| 0 | CWE-119 | Buffer Overflow | ~1,497 |
| 1 | CWE-125 | Out-of-bounds Read | ~441 |
| 2 | CWE-17 | Code | ~37 |
| 3 | CWE-189 | Numeric Errors | ~239 |
| 4 | CWE-19 | Data Processing Errors | ~42 |
| 5 | CWE-190 | Integer Overflow | ~218 |
| 6 | CWE-20 | Input Validation | ~795 |
| 7 | CWE-200 | Information Exposure | ~356 |
| 8 | CWE-254 | Security Features | ~88 |
| 9 | CWE-264 | Permissions/Privileges | ~345 |
| 10 | CWE-284 | Access Control | ~118 |
| 11 | CWE-310 | Cryptographic Issues | ~62 |
| 12 | CWE-362 | Race Condition | ~186 |
| 13 | CWE-399 | Resource Management | ~519 |
| 14 | CWE-404 | Resource Close | ~45 |
| 15 | CWE-415 | Double Free | ~55 |
| 16 | CWE-416 | Use After Free | ~226 |
| 17 | CWE-476 | NULL Pointer Dereference | ~158 |
| 18 | CWE-59 | Link Following | ~39 |
| 19 | CWE-732 | Incorrect Permissions | ~46 |
| 20 | CWE-772 | Resource Leak | ~36 |
| 21 | CWE-787 | Out-of-bounds Write | ~134 |
| 22 | CWE-79 | XSS | ~37 |
| 23 | Other | 61 rare CWE types combined | ~415 |

Full mapping saved at: `logs/cwe_label_map.json`

---

## Test Set Results

| Metric | Value |
|--------|-------|
| **Macro-Recall** | **0.4348** |
| **Macro-F1** | **0.3213** |
| Macro-Precision | 0.2872 |
| Weighted-F1 | 0.3116 |
| Accuracy | 0.3189 |
| Loss | 2.1528 |

---

## Per-Class Performance

| CWE Class | Precision | Recall | F1 | Support | Accuracy |
|-----------|-----------|--------|----|---------|----------|
| CWE-119 | 0.6242 | 0.3209 | 0.4239 | 321 | 32.1% |
| CWE-125 | 0.3650 | 0.5319 | 0.4329 | 94 | 53.2% |
| CWE-17 | 0.3750 | 0.3750 | 0.3750 | 8 | 37.5% |
| CWE-189 | 0.3256 | 0.2745 | 0.2979 | 51 | 27.5% |
| CWE-19 | 0.3333 | 0.4444 | 0.3810 | 9 | 44.4% |
| CWE-190 | 0.3333 | 0.5319 | 0.4098 | 47 | 53.2% |
| CWE-20 | 0.3171 | 0.1529 | 0.2063 | 170 | 15.3% |
| CWE-200 | 0.2353 | 0.1053 | 0.1455 | 76 | 10.5% |
| CWE-254 | 0.1463 | 0.3158 | 0.2000 | 19 | 31.6% |
| CWE-264 | 0.3023 | 0.3514 | 0.3250 | 74 | 35.1% |
| CWE-284 | 0.3043 | 0.5385 | 0.3889 | 26 | 53.8% |
| CWE-310 | 0.3226 | 0.7692 | 0.4545 | 13 | 76.9% |
| CWE-362 | 0.1892 | 0.3500 | 0.2456 | 40 | 35.0% |
| CWE-399 | 0.3022 | 0.3750 | 0.3347 | 112 | 37.5% |
| CWE-404 | 0.2759 | 0.8889 | 0.4211 | 9 | 88.9% |
| CWE-415 | 0.4500 | 0.7500 | **0.5625** | 12 | 75.0% |
| CWE-416 | 0.1220 | 0.1020 | 0.1111 | 49 | 10.2% |
| CWE-476 | 0.1923 | 0.4545 | 0.2703 | 33 | 45.5% |
| CWE-59 | 0.2500 | 0.7500 | 0.3750 | 8 | 75.0% |
| CWE-732 | 0.3684 | 0.7778 | 0.5000 | 9 | 77.8% |
| CWE-772 | 0.1176 | 0.5000 | 0.1905 | 8 | 50.0% |
| CWE-787 | 0.2093 | 0.3103 | 0.2500 | 29 | 31.0% |
| CWE-79 | 0.2308 | 0.3750 | 0.2857 | 8 | 37.5% |
| Other | 0.2000 | 0.0899 | 0.1240 | 89 | 9.0% |

---

## Worst-Performing CWE Classes & Hypotheses

### 1. CWE-416 (Use After Free) — F1 = 0.1111

**Why:** CWE-416 is structurally very similar to CWE-119 (Buffer Overflow) and CWE-125 (Out-of-bounds Read). All three involve improper memory access patterns. The model confuses Use-After-Free with buffer overflows because the code patterns (pointer dereference, memory allocation/deallocation) look similar at the token level. Distinguishing them often requires understanding the *temporal sequence* of alloc → free → use, which is hard to capture in a single function encoding.

### 2. Other (61 rare CWEs) — F1 = 0.1240

**Why:** The "Other" bucket is a catch-all of 61 heterogeneous CWE types. There is no single coherent pattern — it contains everything from race conditions to integer underflows to format string bugs. The model cannot learn a meaningful representation for such a diverse class. This is an inherent limitation of the bucketing approach: it reduces the number of classes but makes the bucket class itself very hard to classify.

### 3. CWE-200 (Information Exposure) — F1 = 0.1455

**Why:** CWE-200 is a *semantic* vulnerability — it depends on *what data* is being exposed, not on a syntactic pattern in the code. Two functions with identical structure could be CWE-200 (if the data is sensitive) or completely fine (if the data is public). The model, which primarily learns token-level patterns, struggles with this distinction. Information exposure detection fundamentally requires understanding data sensitivity, which is beyond the scope of code pattern matching.

---

## Confusion Matrix

The full 24×24 confusion matrix is saved in:
- `logs/phase2_cwe_results.json` (field: `"confusion_matrix"`)
- `results/phase2_cwe_classification/cwe_results.json`

Key observations from the diagonal:
- **Best diagonal accuracy:** CWE-404 (88.9%), CWE-310 (76.9%), CWE-732 (77.8%)
- **Worst diagonal accuracy:** Other (9.0%), CWE-416 (10.2%), CWE-200 (10.5%)
- Classes with distinctive code patterns (crypto, double-free, resource management) are easier to classify
- Classes defined by semantic intent (information exposure, generic "Other") are hardest

---

## Running CWE Inference

### CLI

```bash
python src/evaluation/evaluate_cwe.py --predict \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

Output:
```
  Top-3 CWE Predictions:
    1. CWE-119         13.51%
    2. CWE-264          9.52%
    3. Other            8.82%
```

### Python API

```python
import torch
from src.data.dataset import get_tokenizer
from src.models.train_cwe import CodeT5CWEClassifier
from peft import PeftModel
import json

# Load class names
with open("logs/cwe_label_map.json") as f:
    meta = json.load(f)
class_names = meta["class_names"]

# Load model
tokenizer = get_tokenizer("codet5")
base = CodeT5CWEClassifier("Salesforce/codet5-base", num_classes=len(class_names))
model = PeftModel.from_pretrained(base, "models/saved/codet5_cwe_best")
model.eval()

# Predict
code = "int main() { char buf[10]; gets(buf); return 0; }"
inputs = tokenizer(code, max_length=256, padding="max_length",
                   truncation=True, return_tensors="pt")

with torch.no_grad():
    logits = model(input_ids=inputs["input_ids"],
                   attention_mask=inputs["attention_mask"]).logits
    probs = torch.softmax(logits, dim=-1)
    top3 = probs[0].topk(3)

for prob, idx in zip(top3.values, top3.indices):
    print(f"  {class_names[idx]}: {prob:.2%}")
```

---

## Output Files

| File | Description |
|------|-------------|
| `models/saved/codet5_cwe_best/` | CWE classifier LoRA checkpoint (best val macro-F1) |
| `logs/train_cwe.log` | Full training log |
| `logs/phase2_cwe_results.json` | Complete metrics, per-class report, confusion matrix |
| `logs/cwe_label_map.json` | CWE-id → class index mapping |
| `results/phase2_cwe_classification/` | Consolidated results with SUMMARY.md |

---

## Known Limitations

1. **Only 8,760 training samples.** Unlike Phase 1 (which used all 20K samples including non-vulnerable), Phase 2 only trains on vulnerable samples. More labeled data would help.

2. **"Other" bucket is too heterogeneous.** The 61 CWEs bucketed into "Other" have no shared pattern. A hierarchical classification (first detect CWE family, then specific type) might work better.

3. **Macro-F1 = 0.32 is modest but expected.** 24-class classification with severe imbalance on short code snippets is inherently hard. State-of-the-art on BigVul CWE classification in the literature reports 0.25–0.40 macro-F1 depending on the number of classes and methodology.

4. **No data augmentation.** Code-level augmentation (variable renaming, dead-code insertion) could help rare classes.

5. **Max token length = 256 may miss long-range patterns.** Some vulnerability patterns (e.g., UAF) depend on code structure across many lines, which may be truncated.

6. **Token-level models miss semantic vulnerabilities.** CWE-200 (Information Exposure) and similar semantic CWEs require understanding *what the data means*, not just code syntax.

---

## What's Next — Phase 3

Phase 3 will focus on **Severity Scoring**:
- Predict continuous CVSS scores (0.0–10.0) as a regression task
- Use the CodeT5 backbone with a regression head
- Evaluate with MAE, MSE, and correlation metrics
- Derive categorical severity (Low/Medium/High/Critical) from predicted scores
