# Phase 3 — Multi-Tier CVSS Severity Scoring (Regression 0–10)

**Project:** SecuraX — AI-Based Framework for Automated Source Code Vulnerability Detection, Multi-Class CWE Classification, Severity Scoring & LLM Code Repair  
**Date:** October 2026  
**Status:** ✅ APPROACH A COMPLETE (Approaches B & C deferred)  
**Execution Environment:** Windows (CUDA, NVIDIA RTX 4000 Ada Generation, bf16) & macOS (Apple Silicon MPS smoke-tests)  
**Prerequisites:** Phase 1 (binary VF detection) and Phase 2 (CWE classification) must be complete.  
**Artifacts Generated:** `models/saved/phase3_winner_<tier>/`, `logs/phase3_severity_results_*.json`, `logs/phase3_winners.json`

---

## Executive Summary

Phase 3 adds **CVSS severity scoring** to the SecuraX pipeline — predicting a continuous score from 0.0 to 10.0 that quantifies the exploitability and impact of detected vulnerabilities. This enables automated vulnerability prioritization ("patch this critical 9.8 before that low 2.1").

**Key Design Decision:** Unlike Phases 1-2 (which found per-tier training essential due to language-dependent vulnerability distributions), CVSS severity is primarily about **exploitability and impact** — attributes that are less syntax-dependent. Phase 3 tests **both per-tier and shared models** to determine which strategy is optimal for severity.

### Approaches Implemented

| Approach | Description | Tiers Trained | Hypothesis |
|---|---|---|---|
| **A** | Single-task severity regression per tier | All 5 tiers separately | Per-tier specialization captures language-specific severity patterns |
| **B** | DeepCVA-style multi-task (VF + CWE + Severity heads) per tier | Tier 1, 2 (C++, PHP), 3 | Shared representation with VF/CWE tasks aids severity prediction |
| **C** | ONE shared severity regressor across ALL tiers | All tiers combined | CVSS is language-agnostic; pooled data gives more training signal |

---

## 1. Severity Data Overview

| Tier | Language(s) | Train | Val | Test | Total | CVSS Range | Mean ± Std |
|---|---|:---:|:---:|:---:|:---:|---|---|
| **Tier 1** | C / C++ | 1,842 | 367 | 368 | 2,577 | [1.2, 10.0] | 5.47 ± 1.72 |
| **Tier 2** | C++ | 269 | 37 | 38 | 344 | [1.9, 10.0] | 5.16 ± 1.70 |
| **Tier 2** | Python | 265 | 33 | 34 | 332 | [1.9, 10.0] | 5.34 ± 1.63 |
| **Tier 2** | PHP | 892 | 167 | 167 | 1,226 | [2.1, 10.0] | 5.25 ± 1.50 |
| **Tier 3** | Shared (7 langs) | 1,269 | 235 | 235 | 1,739 | [1.9, 10.0] | 5.45 ± 1.60 |
| **Combined** | All tiers | 4,537 | 839 | 842 | 6,218 | [1.2, 10.0] | 5.38 ± 1.63 |

### CVSS Score Distribution (Training Set)

| Band | Tier 1 | Tier 2 C++ | Tier 2 Python | Tier 2 PHP | Tier 3 | Combined |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Low (0–3.9)** | 199 (10.8%) | 36 (13.4%) | 30 (11.3%) | 134 (15.0%) | 150 (11.8%) | 549 (12.1%) |
| **Medium (4–6.9)** | 1,239 (67.3%) | 189 (70.3%) | 187 (70.6%) | 603 (67.6%) | 823 (64.9%) | 3,041 (67.0%) |
| **High (7–8.9)** | 355 (19.3%) | 39 (14.5%) | 39 (14.7%) | 143 (16.0%) | 263 (20.7%) | 839 (18.5%) |
| **Critical (9–10)** | 49 (2.7%) | 5 (1.9%) | 9 (3.4%) | 12 (1.3%) | 33 (2.6%) | 108 (2.4%) |

> **Key observation:** The Medium band (4.0–6.9) dominates across all tiers (~67%), reflecting the real-world distribution of vulnerability severity. Critical scores (9.0+) are rare (~2.4%).

---

## 2. Architecture

### 2.1 Model Design

| Component | Detail |
|---|---|
| **Encoder** | CodeT5-base or GraphCodeBERT-base (reuses Phase 1/2 winning encoders) |
| **Pooling** | LineVul-style AttentionPooling (consistent with Phases 1-2) |
| **Regression Head** | Linear(768 → 256) → ReLU → Dropout(0.1) → Linear(256 → 1) → Sigmoid |
| **Output Range** | Sigmoid output [0, 1] × 10 = CVSS [0, 10] |
| **Fine-Tuning** | LoRA $r=64$, $\alpha=128$ (consistent with Phases 1-2) |

### 2.2 Training Recipe

| Parameter | Value |
|---|---|
| **Loss** | SmoothL1Loss (Huber, $\delta=1.0$) — robust to outlier CVSS scores |
| **Optimizer** | AdamW ($\text{lr} = 2 \times 10^{-4}$, weight decay = 0.01) |
| **Scheduler** | CosineAnnealingLR ($\eta_{\min} = 0.1 \times \text{lr}$) |
| **Max Token Length** | 512 |
| **Batch Size** | 32 (effective 64 with grad_accum=2) |
| **Early Stopping** | Patience=5 on val MAE (lower is better) |
| **Precision** | bfloat16 mixed precision (CUDA) |
| **Normalization** | CVSS scores normalized to [0, 1] during training, denormalized for evaluation |

### 2.3 Evaluation Metrics

| Metric | Formula | Interpretation |
|---|---|---|
| **MAE** | $\frac{1}{n}\sum|y_i - \hat{y}_i|$ | Average absolute error in CVSS points (primary metric) |
| **RMSE** | $\sqrt{\frac{1}{n}\sum(y_i - \hat{y}_i)^2}$ | Root mean squared error — penalizes large errors more |
| **R²** | $1 - \frac{\sum(y_i - \hat{y}_i)^2}{\sum(y_i - \bar{y})^2}$ | Coefficient of determination (1.0 = perfect, 0.0 = mean baseline) |
| **Pearson ρ** | Correlation coefficient | Measures linear correlation between predicted and true scores |
| **Band Accuracy** | $\frac{\text{correct band predictions}}{\text{total}}$ | Low/Medium/High/Critical band classification accuracy |

---

## 3. Approach Details

### 3.1 Approach A — Single-Task Per-Tier Regression

Each tier gets its own dedicated severity regressor, using the Phase 1 winning encoder as initialization.

| Tier | Encoder | Warm-Start | Train Samples |
|---|---|---|:---:|
| Tier 1 (C/C++) | CodeT5 + GraphCodeBERT | None (fresh LoRA) | 1,842 |
| Tier 2 (C++) | GraphCodeBERT | Phase 1 Tier 1 winner | 269 |
| Tier 2 (Python) | GraphCodeBERT | Phase 1 Tier 1 winner | 265 |
| Tier 2 (PHP) | CodeT5 | Phase 1 Tier 1 winner | 892 |
| Tier 3 (Shared) | CodeT5 + `<LANG=xx>` | None | 1,269 |

**Rationale:** Maximizes specialization per language family. Risk: small Tier 2 datasets (269–892 samples) may cause overfitting.

### 3.2 Approach B — DeepCVA Multi-Task Per-Tier

Adapted from Le et al., *DeepCVA: Automated Commit-Level Vulnerability Assessment* (ASE 2021; [github.com/lhmtriet/DeepCVA](https://github.com/lhmtriet/DeepCVA)).

A shared encoder feeds three task-specific heads:
1. **VF Head:** Binary vulnerability detection (Linear → 2)
2. **CWE Head:** 15-class CWE classification (Linear → 15)
3. **Severity Head:** CVSS regression (MLP → 1)

The multi-task loss balances all three objectives:
$$\mathcal{L}_{\text{total}} = \alpha_1 \mathcal{L}_{\text{VF}} + \alpha_2 \mathcal{L}_{\text{CWE}} + \alpha_3 \mathcal{L}_{\text{Severity}}$$

**Rationale:** The shared encoder learns representations useful for all three tasks. DeepCVA showed 24.4% improvement in accuracy and 6.3× efficiency over separate single-task models.

### 3.3 Approach C — ONE Shared Cross-Tier Regressor

A single severity model trained on **all 4,537 training samples** across all tiers, with `<LANG=xx>` token prefixes for language conditioning.

**Rationale:** CVSS severity measures exploitability and impact — properties that depend more on the *type* of vulnerability (buffer overflow → memory corruption → high severity) than on the programming language. Pooling all tiers gives 2.5× more training data than Tier 1 alone.

---

## 4. Reference Implementations

### 4.1 AIBugHunter (Fu et al., 2024)

- **Paper:** *An Empirical Study of AI Bug Hunters in Practice*, Empirical Software Engineering
- **Repository:** [github.com/awsm-research/AIBugHunter](https://github.com/awsm-research/AIBugHunter)
- **Component Used:** `rq3_cvss_score_reg/bert/` — pretrained CodeBERT regression checkpoint
- **Adaptation:** Fine-tuned on our Tier 1 C/C++ severity split with updated LoRA recipe

### 4.2 DeepCVA (Le et al., 2021)

- **Paper:** *DeepCVA: Automated Commit-Level Vulnerability Assessment*, ASE 2021
- **Repository:** [github.com/lhmtriet/DeepCVA](https://github.com/lhmtriet/DeepCVA)
- **Adaptation:** Shared-encoder multi-task design with our AttentionPooling + LoRA recipe

---

## 5. Exact Reproduction Commands

### Windows PowerShell (CUDA, RTX 4000)

```powershell
# Activate environment
cd D:\Minor_Project-PD\SecuraX
.venv\Scripts\activate

# ══════════════════════════════════════════════════════════════════════
# OPTION 1: Automated orchestrator (all 12 runs)
# ══════════════════════════════════════════════════════════════════════

# Dry run first
python src/models/run_phase3_all_tiers.py --dry-run

# Full execution (~6-8 hours total)
python src/models/run_phase3_all_tiers.py --bf16 --epochs 15

# Only Approach A (per-tier)
python src/models/run_phase3_all_tiers.py --only-approach A --bf16

# Only Approach C (shared)
python src/models/run_phase3_all_tiers.py --only-approach C --bf16

# ══════════════════════════════════════════════════════════════════════
# OPTION 2: Step-by-step individual training
# ══════════════════════════════════════════════════════════════════════

# ── Approach A: Single-task per-tier ──
# Tier 1 (1,842 severity samples, ~1 hour each)
python src/models/train_severity.py --approach A --model codet5 --tier tier1_c_cpp --bf16 --epochs 15
python src/models/train_severity.py --approach A --model graphcodebert --tier tier1_c_cpp --bf16 --epochs 15

# Tier 2 (small datasets, ~15-30 min each)
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_cpp --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_python --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach A --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp

# Tier 3 (1,269 samples, ~45 min)
python src/models/train_severity.py --approach A --model codet5 --tier tier3_shared --bf16 --use-lang-tokens

# ── Approach B: Multi-task per-tier (DeepCVA-style) ──
python src/models/train_severity.py --approach B --model graphcodebert --tier tier1_c_cpp --bf16
python src/models/train_severity.py --approach B --model graphcodebert --tier tier2_cpp --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach B --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach B --model codet5 --tier tier3_shared --bf16 --use-lang-tokens

# ── Approach C: ONE shared cross-tier regressor ──
python src/models/train_severity.py --approach C --model codet5 --bf16
python src/models/train_severity.py --approach C --model graphcodebert --bf16

# ══════════════════════════════════════════════════════════════════════
# EVALUATION
# ══════════════════════════════════════════════════════════════════════

# Consolidated comparison table
python src/models/train_severity.py --evaluate-all

# Per-tier detailed breakdown
python src/evaluation/evaluate_severity.py --compare-all

# Per-tier vs shared comparison
python src/evaluation/evaluate_severity.py --per-tier-vs-shared

# Select and export winners
python src/evaluation/evaluate_severity.py --select-winners
```

### macOS (Apple Silicon MPS Smoke Tests)

```bash
cd SecuraX
source .venv/bin/activate

# Quick smoke-test on MPS (small sample)
python src/models/train_severity.py --approach A --model codet5 --tier tier1_c_cpp --epochs 2 --batch-size 4 --max-samples 100

# Shared model smoke-test
python src/models/train_severity.py --approach C --model codet5 --epochs 2 --batch-size 4 --max-samples 200
```

---

## 6. Saved Artifacts

### Model Checkpoints

```
models/saved/
├── phase3_A_tier1_c_cpp_codet5/           # Approach A, Tier 1, CodeT5
├── phase3_A_tier1_c_cpp_graphcodebert/     # Approach A, Tier 1, GraphCodeBERT
├── phase3_A_tier2_cpp_graphcodebert/       # Approach A, Tier 2 C++
├── phase3_A_tier2_python_graphcodebert/    # Approach A, Tier 2 Python
├── phase3_A_tier2_php_codet5/             # Approach A, Tier 2 PHP
├── phase3_A_tier3_shared_codet5/          # Approach A, Tier 3 Shared
├── phase3_B_tier1_c_cpp_graphcodebert/    # Approach B, Tier 1 Multi-Task
├── phase3_B_tier2_cpp_graphcodebert/      # Approach B, Tier 2 C++ Multi-Task
├── phase3_B_tier2_php_codet5/            # Approach B, Tier 2 PHP Multi-Task
├── phase3_B_tier3_shared_codet5/         # Approach B, Tier 3 Multi-Task
├── phase3_C_all_shared_codet5/           # Approach C, Shared CodeT5
├── phase3_C_all_shared_graphcodebert/    # Approach C, Shared GraphCodeBERT
└── phase3_winner_<tier>/                  # Winner per tier
```

### Result Logs

```
logs/
├── phase3_severity_results_phase3_A_*.json    # Approach A result JSONs
├── phase3_severity_results_phase3_B_*.json    # Approach B result JSONs
├── phase3_severity_results_phase3_C_*.json    # Approach C result JSONs
└── phase3_winners.json                         # Consolidated winner selection
```

---

## 7. Known Limitations & Considerations

1. **Severity data is sparse** — Only 6,218 total samples with CVSS scores (vs 540K for VF detection). This makes overfitting a significant risk, especially for Tier 2 C++ (344 samples) and Python (332 samples).

2. **Medium-band dominance** — ~67% of all CVSS scores fall in the 4.0–6.9 range. Models may develop a "mean regression" bias, predicting ~5.0 for everything. The SmoothL1Loss and per-band evaluation help diagnose this.

3. **CVSS version heterogeneity** — The dataset mixes CVSS v2 and v3 scores from different sources (NVD, GitHub Security Advisories). This introduces measurement noise.

4. **DeepCVA multi-task dependency** — Approach B requires VF labels and CWE labels alongside severity labels, which limits it to samples that have all three annotations.

5. **Shared vs per-tier is an empirical question** — The master prompt explicitly asks us to NOT assume which wins. CVSS severity is about exploitability/impact (less syntax-dependent), so the shared model may win — but this must be verified with numbers.

---

## 8. Handoff to Phase 4

With severity scoring complete, the pipeline advances to **Phase 4 — LLM-Based Code Refinement** (Mistral-7B-Instruct / DeepSeek-Coder), which generates patched code for detected vulnerabilities.

---

*Phase 3 documentation | Seed: 42 | Split ratios: 70/15/15*
