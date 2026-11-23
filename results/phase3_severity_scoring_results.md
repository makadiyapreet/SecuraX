# SecuraX — Phase 3: Multi-Tier CVSS Severity Scoring Results

> **Date:** October 2026  
> **Status:** ✅ APPROACH A COMPLETE (Approaches B & C deferred)  
> **Training Environment:** Windows (CUDA, NVIDIA RTX 4000 Ada Generation, bf16)  
> **Scripts:** `src/models/train_severity.py`, `src/models/run_phase3_all_tiers.py`  
> **Output Artifacts:** `models/saved/phase3_A_*`, `logs/phase3_severity_results_*.json`

---

## Executive Summary

Phase 3 predicts **CVSS severity scores (0–10 continuous)** for detected vulnerabilities using three approaches:
- **Approach A:** Single-task severity regression per tier — ✅ **COMPLETE**
- **Approach B:** DeepCVA-style multi-task (VF + CWE + Severity) per tier — ❌ Deferred
- **Approach C:** ONE shared severity regressor across all tiers — ❌ Deferred

**Total severity samples:** 6,218 across all tiers (train: 4,537 / val: 839 / test: 842)

---

## 1. Severity Data Overview

| Tier | Language(s) | Train | Val | Test | Total | Mean CVSS | Std |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | 1,842 | 367 | 368 | 2,577 | 5.47 | 1.72 |
| **Tier 2** | C++ | 269 | 37 | 38 | 344 | 5.16 | 1.70 |
| **Tier 2** | Python | 265 | 33 | 34 | 332 | 5.34 | 1.63 |
| **Tier 2** | PHP | 892 | 167 | 167 | 1,226 | 5.25 | 1.50 |
| **Tier 3** | Shared (7 langs) | 1,269 | 235 | 235 | 1,739 | 5.45 | 1.60 |
| **Combined** | All | **4,537** | **839** | **842** | **6,218** | **5.38** | **1.63** |

---

## 2. Approach A Results — Single-Task Per-Tier Regression

### 2.1 Test Set Metrics (Final)

| Tier | Model | Best Epoch | Val MAE | Test MAE | Test RMSE | Test R² | Pearson ρ | Band Acc |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Tier 1 C/C++** | **CodeT5** ⭐ | 1 | 1.384 | **1.357** | 1.777 | -0.154 | -0.020 | **67.66%** |
| **Tier 1 C/C++** | GraphCodeBERT | 4 | 1.378 | 1.447 | 1.878 | -0.288 | -0.023 | 67.66% |
| **Tier 2 C++** | GraphCodeBERT | 2 | 1.288 | 1.499 | 2.038 | -0.187 | -0.219 | **68.42%** |
| **Tier 2 Python** | GraphCodeBERT | 5 | 0.941 | **1.269** | 1.643 | -0.016 | -0.089 | **73.53%** |
| **Tier 2 PHP** | **CodeT5** ⭐ | 15 | 1.040 | **1.167** | 1.454 | -0.009 | 0.082 | **68.26%** |
| **Tier 3 Shared** | CodeT5 | 13 | **1.200** | — | — | — | — | — |

> **Tier 3 note:** Training completed (best val MAE = 1.200 at epoch 13), but test evaluation was interrupted — no test metrics JSON was generated. The model checkpoint at `models/saved/phase3_A_tier3_shared_codet5/` is saved and usable.

### 2.2 Per-Band MAE Breakdown

| Tier | Model | Low (0–3.9) | Medium (4–6.9) | High (7–8.9) | Critical (9–10) |
|---|---|:---:|:---:|:---:|:---:|
| **Tier 1** | CodeT5 ⭐ | 2.59 | **0.73** | 2.49 | 4.92 |
| **Tier 1** | GraphCodeBERT | 2.33 | 0.81 | 2.72 | 5.21 |
| **Tier 2 C++** | GraphCodeBERT | 2.20 | **0.78** | 2.85 | 5.39 |
| **Tier 2 Python** | GraphCodeBERT | 2.20 | **0.80** | 2.37 | 4.97 |
| **Tier 2 PHP** | CodeT5 ⭐ | 1.35 | **0.80** | 2.63 | 4.48 |

### 2.3 Per-Tier Winners (Approach A Only)

| Tier | 🏆 Winner | Test MAE | Test RMSE | Band Acc | Checkpoint |
|---|---|:---:|:---:|:---:|---|
| **Tier 1 C/C++** | **CodeT5** | **1.357** | 1.777 | 67.66% | `models/saved/phase3_A_tier1_c_cpp_codet5/` |
| **Tier 2 C++** | GraphCodeBERT | 1.499 | 2.038 | 68.42% | `models/saved/phase3_A_tier2_cpp_graphcodebert/` |
| **Tier 2 Python** | GraphCodeBERT | 1.269 | 1.643 | 73.53% | `models/saved/phase3_A_tier2_python_graphcodebert/` |
| **Tier 2 PHP** | **CodeT5** | **1.167** | 1.454 | 68.26% | `models/saved/phase3_A_tier2_php_codet5/` |
| **Tier 3 Shared** | CodeT5 | — (val=1.200) | — | — | `models/saved/phase3_A_tier3_shared_codet5/` |

---

## 3. Key Observations

1. **Mean-regression bias is dominant.** All R² values are negative (worse than predicting the mean), and Pearson ρ is near zero. This indicates models are largely collapsing toward predicting ~5.0 (the population mean) rather than learning severity-discriminative features.

2. **Medium-band accuracy drives band accuracy.** The ~67–74% band accuracy is primarily explained by correct Medium-band predictions (MAE ≈ 0.7–0.8), while Critical band predictions are off by ~5 CVSS points on average.

3. **CVSS prediction is fundamentally hard from code alone.** Severity scores encode exploitability, impact scope, and attack complexity — factors that are poorly captured by function-level source code tokens. This is consistent with literature findings (AIBugHunter achieved ~1.5 MAE on similar data).

4. **Best overall model: Tier 2 PHP CodeT5** (MAE = 1.167), likely because PHP had the most balanced severity distribution and CodeT5 trained for the full 15 epochs without early stopping.

5. **Approaches B (multi-task) and C (shared) were not trained** due to computational resource constraints and the Phase 4 priority. These remain as future ablations.

---

## 4. Training Details

### 4.1 Common Hyperparameters

| Parameter | Value |
|---|---|
| **Loss** | SmoothL1Loss (Huber, δ=1.0) |
| **Optimizer** | AdamW (lr = 2×10⁻⁴, weight decay = 0.01) |
| **Scheduler** | CosineAnnealingLR (η_min = 0.1 × lr) |
| **LoRA** | r=64, α=128, dropout=0.1 |
| **Max Length** | 512 tokens |
| **Batch Size** | 32 (effective 64 with grad_accum=2) |
| **Precision** | bfloat16 mixed precision (CUDA) |
| **Early Stopping** | Patience=5 on val MAE |

### 4.2 Training Time per Run

| Run | Epochs | Time per Epoch | Total |
|---|:---:|---|---|
| Tier 1 CodeT5 | 6 (ES) | ~54 min | ~5.4h |
| Tier 1 GraphCodeBERT | 9 (ES) | ~2.3h | ~21h |
| Tier 2 C++ GraphCodeBERT | 7 (ES) | ~15 min | ~1.8h |
| Tier 2 Python GraphCodeBERT | 10 (ES) | ~11 min | ~1.8h |
| Tier 2 PHP CodeT5 | 15 (full) | ~1.5h | ~22h |
| Tier 3 Shared CodeT5 | 15 (ES at 13) | ~2h | ~30h |

---

## 5. Reproduction Commands

```powershell
# Activate environment
cd D:\Minor_Project-PD\SecuraX
.venv\Scripts\activate

# Approach A — Per-tier (the only approach with results)
python src/models/train_severity.py --approach A --model codet5 --tier tier1_c_cpp --bf16 --epochs 15
python src/models/train_severity.py --approach A --model graphcodebert --tier tier1_c_cpp --bf16 --epochs 15
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_cpp --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_python --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach A --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach A --model codet5 --tier tier3_shared --bf16 --use-lang-tokens
```

---

## 6. Known Limitations

1. **Only Approach A completed** — Approaches B (multi-task DeepCVA) and C (shared cross-tier) were deferred to prioritize Phase 4.
2. **Tier 3 missing test metrics** — Training completed successfully but test evaluation was interrupted.
3. **Negative R² across the board** — Models underperform mean-baseline prediction, indicating CVSS is not well-predicted from code tokens alone.
4. **CVSS version mixing** — Dataset combines CVSS v2 and v3 scores, introducing measurement noise.
5. **Sparse training data** — Only 6,218 samples with CVSS (vs 540K for VF detection), especially small for Tier 2 C++ (269) and Python (265).

---

*Phase 3 results populated from actual training runs | Seed: 42 | Split ratios: 70/15/15*
