# Phase 2 (v1 — Superseded): 24-Class CWE Classification Baseline

> [!WARNING]
> **SUPERSEDED ARCHITECTURE:** This document records the initial Phase 2 v1 iteration (24-class, arbitrary rare-class grouping).  
> It has been superseded by **Phase 2 v2** (15-class MITRE semantic grouping with LoRA $r=64$, Focal Loss, WeightedRandomSampler, and debugged multi-model ensembling).  
> See [docs/PHASE_2.md](docs/PHASE_2.md) for the active, multi-tier implementation.

**Project:** SecuraX — AI-Based Framework for Automated Source Code Vulnerability Detection  
**Date:** September 2026 (Superseded October 2026)  
**Initial Goal:** Train a multi-class CWE classifier on top of the CodeT5 backbone using an arbitrary cutoff threshold (<50 samples $\rightarrow$ "Other").

---

## 1. Why Phase 2 v1 Was Superseded

The initial Phase 2 implementation attempted 24-class classification on BigVul C/C++ data by grouping any CWE with fewer than 50 samples into an arbitrary "Other" bucket. This design suffered from three critical flaws:

1. **Incoherent "Other" Bucket:** Merging 61 diverse vulnerability types (ranging from cryptographic flaws to race conditions to XML injection) into a single "Other" label created an incoherent representation space that degraded model learning.
2. **Confused Memory Safety Semantics:** High-frequency classes such as CWE-119 (Buffer Overflow), CWE-416 (Use-After-Free), and CWE-125 (Out-of-Bounds Read) were trained as disjoint flat labels without capturing hierarchical relationships, causing severe misclassifications between related memory corruption types.
3. **Low Recall on Critical Vulnerabilities:** Due to standard weighted CrossEntropy and lower LoRA capacity ($r=16, \alpha=32$), the model achieved poor macro performance:
   - **Macro-Recall:** **0.4348**
   - **Macro-F1:** **0.3213**
   - **Weighted-F1:** 0.3116
   - **Accuracy:** 0.3189

---

## 2. Phase 2 v1 Architecture & Hyperparameters (Archival)

| Parameter | v1 Baseline (Superseded) | v2 Improvement |
|---|---|---|
| **Class Scheme** | 24 classes (23 CWEs + arbitrary "Other") | **15 semantic groups** (MITRE CWE-1000 research view) |
| **LoRA Rank ($r$)** | 16 | **64** (higher parameter capacity) |
| **LoRA Alpha ($\alpha$)** | 32 | **128** |
| **LoRA Targets** | `["q", "v"]` (attention only) | All attention projections (`q, k, v, o` / `query, key, value, dense`) |
| **Loss Function** | Weighted Cross-Entropy (clamped 10×) | **Focal Loss** ($\gamma = 2.0$) + inverse-frequency weights |
| **Sampling** | Random stratified | **WeightedRandomSampler** (minority oversampling) |
| **Max Sequence Length** | 256 tokens | **512 tokens** |
| **Backbones Evaluated** | CodeT5 only | **CodeT5**, **GraphCodeBERT**, and **CodeBERT-MOO** (AIBugHunter) |
| **Multi-Tier Support** | C/C++ only | **All 3 Tiers** (C/C++, Python, C++, PHP, Shared Tier 3) |

---

## 3. Phase 2 v1 Results (Archival)

### Overall Test Metrics (CodeT5-v1)

| Metric | Score | Note |
|---|:---:|---|
| **Macro-Recall** | 0.4348 | Failed on 8 of 24 classes (F1 < 0.15) |
| **Macro-F1** | 0.3213 | Poor generalization on rare security bugs |
| **Weighted-F1** | 0.3116 | Pulled down by massive class imbalances |
| **Accuracy** | 0.3189 | Barely outperforms dominant class prior |

### Worst Classes in v1

* **CWE-415 (Double Free):** F1 = 0.0000 (completely missed)
* **CWE-362 (Race Condition):** F1 = 0.0526
* **CWE-787 (Out-of-Bounds Write):** F1 = 0.1143
* **CWE-190 (Integer Overflow):** Confused heavily with CWE-119

---

## 4. Key Transition to Phase 2 v2

To overcome these fundamental limitations, Phase 2 was completely redesigned:
* Re-mapped all 181+ CWEs across datasets into **15 standardized MITRE semantic groups** (Buffer-Overflow, OOB-Read, OOB-Write, Use-After-Free, Double-Free, NULL-Deref, Integer-Issues, Input-Validation, Info-Exposure, Access-Control, Crypto-Issues, Resource-Mgmt, Race-Condition, Path-Traversal, Other-Security).
* Implemented **Focal Loss ($\gamma=2.0$)** and **WeightedRandomSampler** for extreme minority representation.
* Multi-model evaluation comparing CodeT5-v2, GraphCodeBERT-v2, and AIBugHunter Multi-Objective Optimization (MOO).
* Upgraded results: Tier 1 Macro-Recall jumped from **0.4348 $\rightarrow$ 0.6513 (+49.8%)**, and Macro-F1 jumped from **0.3213 $\rightarrow$ 0.6894 (+114.6%)**.

Full v2 multi-tier documentation is maintained in [docs/PHASE_2.md](docs/PHASE_2.md).
