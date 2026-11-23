# Phase 2 — CWE Multi-Class Classification Results

**Task:** Given a **vulnerable** code function, classify which **CWE vulnerability type** it belongs to (24 classes).

**Dataset:** BigVul — 8,760 vulnerable samples with valid CWE IDs

**Primary Metric:** Macro-Recall (equal importance to each CWE class regardless of size)

---

## Model Trained

### CodeT5 CWE Classifier (`cwe_results.json`)
- **What:** Salesforce/codet5-base encoder + mean pooling + dropout + 24-class linear head
- **Fine-tuning:** LoRA (rank=16, α=32) on attention projections `["q", "v"]`
- **Trainable params:** ~591K (0.54% of total)
- **Epochs trained:** 10 (best at epoch 10)
- **Checkpoint:** `models/saved/codet5_cwe_best/`

---

## Class Imbalance Handling

**Problem:** 84 unique CWE classes with severe imbalance:
- Top class (CWE-119): 2,139 samples (24.4%)
- Bottom 27 classes: < 5 samples each

**Strategy (two-pronged):**
1. **Rare-class bucketing:** CWE classes with < 50 samples merged into "Other" → 84 classes reduced to 24
2. **Weighted CrossEntropyLoss:** Inverse-frequency class weights (clamped at 10×) to upweight rare classes

**Label mapping:** See `cwe_label_map.json` for the full CWE-id → class index mapping.

---

## Test Set Results

| Metric | Value |
|--------|-------|
| **Macro-Recall** | **0.4348** |
| **Macro-F1** | **0.3213** |
| Weighted-F1 | 0.3116 |
| Accuracy | 0.3189 |
| Loss | 2.1528 |

---

## Per-Class Performance

| CWE Class | Precision | Recall | F1 | Test Samples | Accuracy |
|-----------|-----------|--------|----|-------------|----------|
| CWE-119 (Buffer Overflow) | 0.6242 | 0.3209 | 0.4239 | 321 | 32.1% |
| CWE-125 (Out-of-bounds Read) | 0.3650 | 0.5319 | 0.4329 | 94 | 53.2% |
| CWE-17 (Code) | 0.3750 | 0.3750 | 0.3750 | 8 | 37.5% |
| CWE-189 (Numeric Errors) | 0.3256 | 0.2745 | 0.2979 | 51 | 27.5% |
| CWE-19 (Data Processing) | 0.3333 | 0.4444 | 0.3810 | 9 | 44.4% |
| CWE-190 (Integer Overflow) | 0.3333 | 0.5319 | 0.4098 | 47 | 53.2% |
| CWE-20 (Input Validation) | 0.3171 | 0.1529 | 0.2063 | 170 | 15.3% |
| CWE-200 (Info Exposure) | 0.2353 | 0.1053 | 0.1455 | 76 | 10.5% |
| CWE-254 (Security Features) | 0.1463 | 0.3158 | 0.2000 | 19 | 31.6% |
| CWE-264 (Permissions) | 0.3023 | 0.3514 | 0.3250 | 74 | 35.1% |
| CWE-284 (Access Control) | 0.3043 | 0.5385 | 0.3889 | 26 | 53.8% |
| CWE-310 (Crypto Issues) | 0.3226 | 0.7692 | 0.4545 | 13 | 76.9% |
| CWE-362 (Race Condition) | 0.1892 | 0.3500 | 0.2456 | 40 | 35.0% |
| CWE-399 (Resource Mgmt) | 0.3022 | 0.3750 | 0.3347 | 112 | 37.5% |
| CWE-404 (Resource Close) | 0.2759 | 0.8889 | 0.4211 | 9 | 88.9% |
| CWE-415 (Double Free) | 0.4500 | 0.7500 | 0.5625 | 12 | 75.0% |
| CWE-416 (Use After Free) | 0.1220 | 0.1020 | 0.1111 | 49 | 10.2% |
| CWE-476 (NULL Deref) | 0.1923 | 0.4545 | 0.2703 | 33 | 45.5% |
| CWE-59 (Link Following) | 0.2500 | 0.7500 | 0.3750 | 8 | 75.0% |
| CWE-732 (Permissions) | 0.3684 | 0.7778 | 0.5000 | 9 | 77.8% |
| CWE-772 (Resource Leak) | 0.1176 | 0.5000 | 0.1905 | 8 | 50.0% |
| CWE-787 (Out-of-bounds Write) | 0.2093 | 0.3103 | 0.2500 | 29 | 31.0% |
| CWE-79 (XSS) | 0.2308 | 0.3750 | 0.2857 | 8 | 37.5% |
| Other (61 rare CWEs) | 0.2000 | 0.0899 | 0.1240 | 89 | 9.0% |

---

## Worst-Performing Classes (and Why)

| Class | F1 | Hypothesis |
|-------|-----|-----------|
| **CWE-416** (Use After Free) | 0.1111 | Structurally similar to CWE-119/CWE-125 (memory errors). The model confuses UAF patterns with buffer overflows since both involve dangling/out-of-bounds memory access. |
| **Other** (61 rare CWEs) | 0.1240 | A catch-all bucket of 61 heterogeneous CWE types. No coherent pattern to learn — each sub-class has too few samples and the "Other" concept is semantically vague. |
| **CWE-200** (Info Exposure) | 0.1455 | High-level semantic vulnerability (what data is exposed) rather than a syntactic pattern. The model lacks the contextual understanding of which data is "sensitive." |

---

## Confusion Matrix

Full 24×24 confusion matrix is in `cwe_results.json` under the `"confusion_matrix"` key.

---

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Dataset | BigVul — 8,760 vulnerable samples |
| Split | 70/15/15 stratified by CWE class |
| Train / Val / Test | 6,132 / 1,314 / 1,314 |
| Num classes | 24 (23 CWEs ≥50 samples + "Other") |
| Batch size | 8 (effective 32 with grad_accum=4) |
| Learning rate | 2e-4 |
| Optimizer | AdamW (weight_decay=0.01) |
| Scheduler | CosineAnnealingLR |
| Max token length | 256 |
| Early stopping | Patience=3 (by macro-F1) |
| Class weight clamping | 10× max |
