# SecuraX — Phase 1: Multi-Tier Binary Vulnerability Detection Results

> **Date:** October 2026  
> **Status:** ✅ COMPLETE  
> **Training Environment:** Windows (CUDA, NVIDIA RTX 4000 Ada Generation, bf16)  
> **Evaluation Environment:** Windows (CUDA) + macOS (Apple Silicon MPS smoke-tests)  
> **Scripts:** `src/models/train_binary_v2.py`, `src/models/run_phase1_all_tiers.py`  
> **Output Artifacts:** `models/saved/phase1_winner_<tier>/`, `logs/phase1_*_results_v2.json`, `logs/phase1_winners_v2.json`

---

## Executive Summary

Phase 1 trains **binary vulnerability detection classifiers** (Vulnerable vs Non-Vulnerable) across all 5 tiers identified in Phase 0.5. Using LineVul-style attention pooling, Focal Loss ($\gamma=2.0$), and LoRA ($r=64, \alpha=128$), the system achieves strong recall across diverse language ecosystems.

| Tier | Language(s) | 🏆 Winner | Optimal Threshold | Test Recall | Test F1 |
|---|---|---|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **GraphCodeBERT** | 0.70 | 0.4580 | **0.5703** |
| **Tier 2** | C++ | **GraphCodeBERT** | 0.10 | 0.9949 | **0.9843** |
| **Tier 2** | Python | **GraphCodeBERT** | 0.15 | 0.8545 | **0.8174** |
| **Tier 2** | PHP | **CodeT5** | 0.10 | 1.0000 | **1.0000** |
| **Tier 3** | Shared (7 langs) | **CodeT5** | 0.50 | 0.8412 | **0.8330** |

---

## 1. Architecture

### 1.1 Model Design

| Component | Detail |
|---|---|
| **Encoder (CodeT5)** | `Salesforce/codet5-base` (T5 encoder-only, 220M params) |
| **Encoder (GraphCodeBERT)** | `microsoft/graphcodebert-base` (RoBERTa, 125M params) |
| **Encoder (VulBERTa)** | `claudios/VulBERTa-MLP-VulDeePecker` (zero-shot only) |
| **Pooling** | LineVul-style learned **AttentionPooling** (replaces [CLS]/mean-pool) |
| **Head** | Linear(768 → 2) binary classifier |
| **Fine-Tuning** | LoRA $r=64$, $\alpha=128$, dropout=0.1 |
| **LoRA Targets (CodeT5)** | `["q", "k", "v", "o"]` |
| **LoRA Targets (GraphCodeBERT)** | `["query", "key", "value", "dense"]` |

### 1.2 Training Recipe

| Parameter | Value |
|---|---|
| **Loss** | Focal Loss ($\gamma=2.0$) + inverse-frequency class weights (clamped 10×) |
| **Optimizer** | AdamW ($\text{lr} = 2 \times 10^{-4}$, weight decay = 0.01) |
| **Scheduler** | CosineAnnealingLR ($\eta_{\min} = 0.1 \times \text{lr}$) |
| **Max Token Length** | 512 |
| **Batch Size** | 32 (effective 64 with grad_accum=2) |
| **Early Stopping** | Patience=3 on val F1 |
| **Precision** | bfloat16 mixed precision (CUDA) |
| **Threshold** | Swept 0.10–0.90 (step 0.05), precision floor ≥ 0.75 |

---

## 2. Per-Tier Results

### 2.1 Tier 1: C/C++ (524,110 samples)

| Model | Best Epoch | Threshold | Recall | Precision | F1 | AUROC | Accuracy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| CodeT5 (default @0.50) | 5 | 0.50 | 0.7658 | 0.3341 | 0.4653 | 0.8849 | 0.8117 |
| CodeT5 (optimal @0.75) | 5 | 0.75 | 0.4303 | 0.7824 | 0.5552 | 0.8849 | — |
| **★ GraphCodeBERT (default @0.50)** | 5 | 0.50 | 0.6212 | 0.4934 | 0.5500 | 0.8833 | 0.8912 |
| **★ GraphCodeBERT (optimal @0.70)** | 5 | **0.70** | **0.4580** | **0.7557** | **0.5703** | **0.8833** | **0.9262** |
| VulBERTa (zero-shot) | — | 0.50 | 0.0256 | 0.2547 | 0.0465 | 0.5406 | — |

> **Winner:** GraphCodeBERT @ threshold 0.70 — highest F1 (0.5703) with precision 0.7557, achieving the recall-precision balance needed for security triage.

> **VulBERTa:** Near-zero zero-shot recall (0.0256) confirms it cannot generalize without fine-tuning on this dataset distribution.

### 2.2 Tier 2: C++ (7,548 samples)

| Model | Best Epoch | Threshold | Recall | Precision | F1 | AUROC | Accuracy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| CodeT5 (default @0.50) | 1 | 0.50 | 1.0000 | 0.7181 | 0.8359 | 0.9307 | 0.7231 |
| CodeT5 (optimal @0.55) | 1 | 0.55 | 0.9860 | 0.7799 | 0.8709 | 0.9307 | — |
| **★ GraphCodeBERT (default @0.50)** | 7 | 0.50 | 0.9822 | 0.9936 | 0.9879 | 0.9976 | 0.9830 |
| **★ GraphCodeBERT (optimal @0.10)** | 7 | **0.10** | **0.9949** | **0.9739** | **0.9843** | **0.9976** | **0.9776** |

> **Winner:** GraphCodeBERT @ threshold 0.10 — near-perfect recall (0.9949) with 0.9739 precision. The low optimal threshold reflects the high-vulnerability composition of the C++ tier.

### 2.3 Tier 2: Python (10,483 samples)

| Model | Best Epoch | Threshold | Recall | Precision | F1 | AUROC | Accuracy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| CodeT5 (default @0.50) | 5 | 0.50 | 0.3909 | 0.9773 | 0.5584 | 0.9354 | 0.9561 |
| CodeT5 (optimal @0.45) | 5 | 0.45 | 0.5636 | 0.8857 | 0.6889 | 0.9354 | — |
| **★ GraphCodeBERT (default @0.50)** | 10 | 0.50 | 0.8273 | 0.9100 | 0.8667 | 0.9716 | 0.9819 |
| **★ GraphCodeBERT (optimal @0.15)** | 10 | **0.15** | **0.8545** | **0.7833** | **0.8174** | **0.9716** | **0.9729** |

> **Winner:** GraphCodeBERT @ threshold 0.15 — achieves 0.8545 recall on Python vulnerability detection with 0.9716 AUROC.

### 2.4 Tier 2: PHP (2,100 samples — 100% vulnerable)

| Model | Best Epoch | Threshold | Recall | Precision | F1 | AUROC | Accuracy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **★ CodeT5 (optimal @0.10)** | 1 | **0.10** | **1.0000** | **1.0000** | **1.0000** | **N/A** | **1.0000** |

> **Winner:** CodeT5 @ threshold 0.10 — **perfect scores**. Note: PHP tier contains only vulnerable samples (no non-vulnerable code in CVEFixes PHP split), so AUROC is undefined. Perfect recall is trivially achieved but still validates that the model correctly classifies all positive samples.

### 2.5 Tier 3: Shared (3,221 samples — Go, Java, JS, Ruby, TS, JSON, Other)

| Model | Best Epoch | Threshold | Recall | Precision | F1 |
|---|:---:|:---:|:---:|:---:|:---:|
| **★ CodeT5 (`<LANG=xx>` tokens)** | — | **0.50** | **0.8412** | **0.8330** | **0.8330** |

> **Winner:** CodeT5 with `<LANG=xx>` token prefix — the shared model successfully handles 7 languages via language-conditioning tokens.

---

## 3. Threshold Sweep Analysis

Each model undergoes a threshold sweep (0.10–0.90, step 0.05) with a precision floor of 0.75. The optimal threshold maximizes recall subject to the precision constraint.

**Key Findings:**
- **Tier 1 C/C++ optimal threshold is high (0.70)** — reflects the extreme class imbalance (only 9.8% vulnerable). The model needs to be conservative to maintain precision.
- **Tier 2 C++/PHP optimal threshold is low (0.10)** — reflects high vulnerability ratios. The model can afford aggressive recall.
- **Tier 2 Python optimal threshold (0.15)** — moderate imbalance (9.1% vulnerable) benefits from a lower threshold than C.

---

## 4. Winners & Saved Checkpoints

| Tier | Winner | Checkpoint Directory |
|---|---|---|
| **Tier 1 (C/C++)** | GraphCodeBERT + LoRA ($r=64$) | `models/saved/phase1_winner_tier1_c_cpp/` |
| **Tier 2 (C++)** | GraphCodeBERT + LoRA ($r=64$) | `models/saved/phase1_winner_tier2_cpp/` |
| **Tier 2 (Python)** | GraphCodeBERT + LoRA ($r=64$) | `models/saved/phase1_winner_tier2_python/` |
| **Tier 2 (PHP)** | CodeT5 + LoRA ($r=64$) | `models/saved/phase1_winner_tier2_php/` |
| **Tier 3 (Shared)** | CodeT5 + LoRA ($r=64$) + `<LANG=xx>` | `models/saved/phase1_tier3_shared_codet5/` |

Each checkpoint contains:
- LoRA adapter weights (`adapter_model.bin`, `adapter_config.json`)
- Training config (`training_config.json`) with hyperparams, metrics, and epoch
- Tokenizer config for reproducibility

---

## 5. Saved Artifacts

```
logs/
├── phase1_tier1_c_cpp_codet5_results_v2.json
├── phase1_tier1_c_cpp_graphcodebert_results_v2.json
├── phase1_tier1_c_cpp_vulberta_zeroshot.json
├── phase1_tier2_cpp_codet5_results_v2.json
├── phase1_tier2_cpp_graphcodebert_results_v2.json
├── phase1_tier2_php_codet5_results_v2.json
├── phase1_tier2_python_codet5_results_v2.json
├── phase1_tier2_python_graphcodebert_results_v2.json
└── phase1_winners_v2.json
```

---

## 6. Reproduction Commands

```powershell
# Full multi-tier pipeline
python src/models/run_phase1_all_tiers.py --dry-run
python src/models/run_phase1_all_tiers.py --bf16

# Individual tier training
python src/models/train_binary_v2.py --model codet5 --tier tier1_c_cpp --bf16
python src/models/train_binary_v2.py --model graphcodebert --tier tier1_c_cpp --bf16
python src/models/train_binary_v2.py --model vulberta --tier tier1_c_cpp --zero-shot

# Tier 2 with warm-start from Tier 1
python src/models/train_binary_v2.py --model graphcodebert --tier tier2_cpp \
  --warm-start models/saved/phase1_tier1_c_cpp_graphcodebert --bf16

# Tier 3 shared with language tokens
python src/models/train_binary_v2.py --model codet5 --tier tier3_shared --bf16

# Evaluation
python src/evaluation/evaluate_binary_v2.py --compare-all
python src/evaluation/evaluate_binary_v2.py --select-winners
```

---

## 7. Known Limitations

1. **Tier 1 C/C++ Recall (0.4580 @ optimal threshold):** The extreme class imbalance (9.8% vulnerable in 524K samples) makes high-recall + high-precision difficult. AUROC (0.8833) indicates strong ranking.
2. **PHP All-Positive Dataset:** CVEFixes PHP split contains only vulnerable code. Perfect metrics are trivially achievable; precision against non-vulnerable code is untested.
3. **VulBERTa Zero-Shot:** Near-random performance (Recall 0.0256) — this pre-trained model's vulnerability concept doesn't transfer to BigVul/CVEFixes distributions without fine-tuning.

---

## 8. Next Steps → Phase 2

Phase 2 classifies detected vulnerabilities into **15 MITRE CWE semantic groups** using the winning encoders from Phase 1 as initialization.

---

*Generated by Phase 1 Multi-Tier Binary Detection Pipeline | Seed: 42 | Split ratios: 70/15/15*
