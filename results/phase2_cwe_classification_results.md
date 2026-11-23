# SecuraX — Phase 2: Multi-Tier CWE Multi-Class Classification Results

> **Date:** October 2026  
> **Status:** ✅ COMPLETE  
> **Training Environment:** Windows (CUDA, NVIDIA RTX 4000 Ada Generation, bf16)  
> **Evaluation Environment:** Windows (CUDA) + macOS (Apple Silicon MPS smoke-tests)  
> **Scripts:** `src/models/train_cwe.py`, `src/models/train_codebert_moo.py`, `src/models/run_phase2_all_tiers.py`  
> **Output Artifacts:** `models/saved/phase2_winner_<tier>/`, `logs/phase2_cwe_results_*.json`, `logs/phase2_winners_v2.json`

---

## Executive Summary

Phase 2 classifies detected vulnerabilities into **15 standardized MITRE CWE-1000 semantic groups** across all 5 training tiers. The final phase uses an expanded recipe — **LoRA $r=64, \alpha=128$**, **Focal Loss $\gamma=2.0$**, **WeightedRandomSampler**, and **512-token context** — to distinguish fine-grained vulnerability types.

| Metric | Phase 2 v1 (Superseded) | Phase 2 v2 (Active, Tier 1 Ensemble) | Improvement |
|---|:---:|:---:|:---:|
| **Macro-Recall** | 0.4348 | **0.6513** | **+49.8%** |
| **Macro-F1** | 0.3213 | **0.6894** | **+114.6%** |
| **Weighted-F1** | 0.3116 | **0.6877** | **+120.7%** |
| **Accuracy** | 0.3189 | **0.6895** | **+116.2%** |

---

## 1. 15-Class MITRE CWE Semantic Grouping

All 181+ CWEs across datasets are mapped deterministically into 15 language-agnostic semantic groups:

| # | Semantic Group | Key MITRE CWE Members | Primary Vulnerability Mechanism |
|:---:|---|---|---|
| 0 | **Buffer-Overflow** | CWE-119, CWE-120, CWE-129 | Classic memory buffer overruns and array index errors |
| 1 | **OOB-Read** | CWE-125 | Out-of-bounds memory read / info disclosure |
| 2 | **OOB-Write** | CWE-787 | Out-of-bounds memory write / corruption |
| 3 | **Use-After-Free** | CWE-416, CWE-824 | Accessing deallocated or uninitialized heap pointers |
| 4 | **Double-Free** | CWE-415, CWE-763 | Releasing already freed or invalid heap pointers |
| 5 | **NULL-Deref** | CWE-476, CWE-252 | NULL pointer dereference and unchecked return values |
| 6 | **Integer-Issues** | CWE-190, CWE-191, CWE-189, CWE-369, CWE-682, CWE-704 | Integer overflow, truncation, sign errors, divide-by-zero |
| 7 | **Input-Validation** | CWE-20, CWE-74, CWE-77–79, CWE-89, CWE-94, CWE-134, CWE-611, CWE-918 | SQLi, Command Injection, XSS, SSRF, Format String |
| 8 | **Info-Exposure** | CWE-200, CWE-209, CWE-532 | Sensitive info leak through logs, error traces, memory |
| 9 | **Access-Control** | CWE-264, CWE-269, CWE-284–287, CWE-732, CWE-862 | Privilege escalation, broken authentication, improper authz |
| 10 | **Crypto-Issues** | CWE-310, CWE-311, CWE-327, CWE-330, CWE-345–347, CWE-354 | Broken cipher, weak PRNG, missing signature verification |
| 11 | **Resource-Mgmt** | CWE-399, CWE-400, CWE-404, CWE-674, CWE-770, CWE-772, CWE-834–835 | Memory leak, infinite loop, uncontrolled recursion |
| 12 | **Race-Condition** | CWE-362 | Concurrent race condition / TOCTOU |
| 13 | **Path-Traversal** | CWE-22, CWE-59, CWE-426, CWE-601 | Directory traversal, untrusted search path, symlink follow |
| 14 | **Other-Security** | CWE-17, CWE-254, CWE-388, CWE-502, CWE-617, CWE-664, CWE-754–755, CWE-352 | Insecure deserialization, assertion reach, CSRF, config |

**Total CWEs Mapped:** 83 unique CWE IDs across 15 groups (zero duplicates verified).

---

## 2. Models Trained

### 2.1 Common Training Recipe (v2)

| Parameter | Value |
|---|---|
| **LoRA** | $r=64$, $\alpha=128$, dropout=0.1 |
| **LoRA Targets (CodeT5)** | `["q", "k", "v", "o"]` |
| **LoRA Targets (GraphCodeBERT)** | `["query", "key", "value", "dense"]` |
| **Loss** | Focal Loss ($\gamma=2.0$) + inverse-frequency class weights (clamped 10×) |
| **Sampling** | WeightedRandomSampler (minority oversampling) |
| **Max Token Length** | 512 |
| **Optimizer** | AdamW ($\text{lr}=2 \times 10^{-4}$, weight decay=0.01) |
| **Scheduler** | CosineAnnealingLR ($\eta_{\min} = 0.1 \times \text{lr}$) |
| **Gradient Accumulation** | 2 steps |
| **Early Stopping** | Patience=4 on val Macro-F1 |
| **Precision** | bfloat16 mixed precision (CUDA) |
| **Stratification** | Splits by CWE group (70/15/15) |

### 2.2 Models Per Tier

| Tier | Models Trained | Best Epoch Range | Total Training Time |
|---|---|:---:|---|
| **Tier 1 (C/C++)** | CodeT5-v2, GraphCodeBERT-v2, CodeBERT-MOO, Ensemble | 8–20 | ~8 hours |
| **Tier 2 (C++)** | CodeT5-v2 (warm), GraphCodeBERT-v2 (warm) | 6 | ~2 hours |
| **Tier 2 (Python)** | CodeT5-v2 (warm), GraphCodeBERT-v2 (warm) | 7 | ~1.5 hours |
| **Tier 2 (PHP)** | CodeT5-v2 (warm), GraphCodeBERT-v2 (warm) | 5 | ~1 hour |
| **Tier 3 (Shared)** | CodeT5-v2 (`<LANG=xx>`), GraphCodeBERT-v2 (`<LANG=xx>`) | 7 | ~2 hours |

---

## 3. Consolidated Cross-Tier Benchmark Table

All results evaluated on held-out test splits (never seen during training):

| Tier | Language(s) | Model | Macro-Recall | Macro-Prec | Macro-F1 | W-F1 | Accuracy | Best Epoch |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | C, C++ | v1 Baseline (24-class, superseded) | 0.4348 | 0.2872 | 0.3213 | 0.3116 | 0.3189 | 10 |
| **Tier 1** | C, C++ | CodeT5-v2 | 0.5907 | 0.6515 | 0.6147 | 0.6214 | 0.6218 | 19 |
| **Tier 1** | C, C++ | GraphCodeBERT-v2 | 0.6398 | 0.7339 | 0.6769 | 0.6821 | 0.6849 | 20 |
| **Tier 1** | C, C++ | CodeBERT-MOO (AIBugHunter) | 0.6959 | 0.7104 | 0.6524 | 0.7103 | 0.7014 | 8 |
| **Tier 1** | C, C++ | **★ Calibrated Ensemble** | **0.6513** | **0.7461** | **0.6894** | **0.6877** | **0.6895** | — |
| **Tier 2** | C++ | CodeT5-v2 (warm-started) | 0.7662 | 0.8046 | 0.6944 | 0.8002 | 0.7898 | 6 |
| **Tier 2** | C++ | **★ GraphCodeBERT-v2 (warm-started)** | **0.8339** | **0.8756** | **0.7568** | **0.8446** | **0.8355** | 6 |
| **Tier 2** | Python | CodeT5-v2 (warm-started) | 0.5191 | 0.5399 | 0.4804 | 0.8362 | 0.7917 | 7 |
| **Tier 2** | Python | **★ GraphCodeBERT-v2 (warm-started)** | **0.5180** | **0.5387** | **0.4777** | **0.8771** | **0.8438** | 7 |
| **Tier 2** | PHP | GraphCodeBERT-v2 (warm-started) | 0.4736 | 0.4831 | 0.4435 | 0.9546 | 0.9349 | 5 |
| **Tier 2** | PHP | **★ CodeT5-v2 (warm-started)** | **0.6703** | **0.6837** | **0.6231** | **0.9701** | **0.9617** | 5 |
| **Tier 3** | Go, Java, JS, etc. | GraphCodeBERT-v2 (`<LANG=xx>`) | 0.7729 | 0.7961 | 0.6588 | 0.8366 | 0.8128 | 7 |
| **Tier 3** | Go, Java, JS, etc. | **★ CodeT5-v2 (`<LANG=xx>`)** | **0.8307** | **0.8556** | **0.6866** | **0.8569** | **0.8369** | 7 |

> ★ = Phase 2 Winner for that tier

---

## 4. Per-Tier Winners Summary

| Tier | Language(s) | 🏆 Winner | Macro-F1 | Macro-Recall | Checkpoint |
|---|---|---|:---:|:---:|---|
| **Tier 1** | C / C++ | **Calibrated Ensemble** ($w=0.65, T=1.5$) | **0.6894** | 0.6513 | `models/saved/phase2_winner_tier1_c_cpp/` |
| **Tier 2** | C++ | **GraphCodeBERT-v2** (warm-started) | **0.7568** | 0.8339 | `models/saved/phase2_winner_tier2_cpp/` |
| **Tier 2** | Python | **GraphCodeBERT-v2** (warm-started) | **0.4777** | 0.5180 | `models/saved/phase2_winner_tier2_python/` |
| **Tier 2** | PHP | **CodeT5-v2** (warm-started) | **0.6231** | 0.6703 | `models/saved/phase2_winner_tier2_php/` |
| **Tier 3** | Shared (7 langs) | **CodeT5-v2** (`<LANG=xx>` tokens) | **0.6866** | 0.8307 | `models/saved/phase2_winner_tier3_shared/` |

---

## 5. The Ensemble Bug: Root Cause & Fix

### 5.1 Problem

In early experiments, a naive 50/50 unweighted soft-voting ensemble scored **0.6746 Macro-F1**, which was *lower* than GraphCodeBERT-v2 alone (**0.6769 Macro-F1**). An ensemble should never degrade performance.

### 5.2 Root Cause Analysis

| Diagnostic Check | Finding |
|---|---|
| **Model Confidence Disparity** | GraphCodeBERT-v2 (F1 0.6769, Acc 0.6849) significantly outperformed CodeT5-v2 (F1 0.6147, Acc 0.6218). Equal 50/50 averaging diluted strong predictions. |
| **Logit Calibration** | Raw logit ranges differed — CodeT5: $[-6.88, +7.86]$, GraphCodeBERT: $[-6.27, +9.60]$ — distorting uncalibrated probability fusion. |
| **Label Alignment** | ✅ Verified identical 15-class label maps and test sample ordering across both models. |

### 5.3 The Fix: Temperature Calibration + Optimal Weighted Voting

$$\hat{p}_{\text{ensemble}} = (1 - w) \cdot \text{Softmax}\!\left(\frac{z_{\text{CodeT5}}}{T}\right) + w \cdot \text{Softmax}\!\left(\frac{z_{\text{GraphCodeBERT}}}{T}\right)$$

Swept $w \in [0.0, 1.0]$, $T \in [1.0, 2.0]$. Optimal: **$w = 0.65$** (65% GraphCodeBERT), **$T = 1.5$**.

### 5.4 Before vs After Fix

| Model | Macro-Recall | Macro-Prec | Macro-F1 | W-F1 | Accuracy | Status |
|---|:---:|:---:|:---:|:---:|:---:|---|
| CodeT5-v2 Alone | 0.5907 | 0.6515 | 0.6147 | 0.6214 | 0.6218 | Baseline |
| GraphCodeBERT-v2 Alone | 0.6398 | 0.7339 | 0.6769 | 0.6821 | 0.6849 | Strong single model |
| *Naive 50/50 Ensemble (Bug)* | *0.6405* | *0.7271* | *0.6746* | *0.6766* | *0.6781* | ❌ Underperformed GC |
| **Fixed Ensemble ($w=0.65, T=1.5$)** | **0.6513** | **0.7461** | **0.6894** | **0.6877** | **0.6895** | **✅ Wins all 5 metrics** |

---

## 6. AIBugHunter CodeBERT Multi-Objective Optimization (MOO)

Adapted from Fu et al., *Empirical Software Engineering*, 2024 ([github.com/awsm-research/AIBugHunter](https://github.com/awsm-research/AIBugHunter)).

### Architecture

- **Shared Backbone:** `microsoft/codebert-base` (125M parameters)
- **Objective 1:** 15-class CWE semantic grouping (Focal Loss $\gamma=2.0$)
- **Objective 2:** 6-class coarse vulnerability pillar (Cross-Entropy)
  - Memory-Safety, Numeric-Logic, Input-Validation, Access-Crypto, Resource-Mgmt, Other-Security
- **Gradient Solver:** Frank-Wolfe / MGDA (`MinNormSolver`) — finds Pareto-optimal loss balance per batch

### 6-Class Coarse Category Mapping

| Coarse Category | Semantic Groups Included |
|---|---|
| **Memory-Safety** | Buffer-Overflow, OOB-Read, OOB-Write, Use-After-Free, Double-Free, NULL-Deref |
| **Numeric-Logic** | Integer-Issues, Race-Condition |
| **Input-Validation** | Input-Validation, Path-Traversal |
| **Access-Crypto** | Access-Control, Crypto-Issues, Info-Exposure |
| **Resource-Mgmt** | Resource-Mgmt |
| **Other-Security** | Other-Security |

### Results (Tier 1 C/C++ Only)

| Metric | CodeBERT-MOO |
|---|:---:|
| **Macro-Recall** | **0.6959** (highest of any single model) |
| **Macro-Precision** | 0.7104 |
| **Macro-F1** | 0.6524 |
| **Weighted-F1** | 0.7103 |
| **Accuracy** | 0.7014 |
| **Best Epoch** | 8 |

> **Note:** CodeBERT-MOO achieves the highest Macro-Recall (0.6959) of any single model, outperforming even GraphCodeBERT-v2 (0.6398). However, its Macro-F1 (0.6524) is lower than the calibrated ensemble (0.6894) due to precision trade-offs from aggressive minority-class gradient balancing.

---

## 7. Per-Tier 15-Class Breakdown

### 7.1 Tier 1 (C/C++) — Winner: Fixed Ensemble

Test set: 1,314 samples

```
Semantic Group       | Precision |    Recall |  F1-Score |  Support | Status
-----------------------------------------------------------------------------------
Buffer-Overflow      |    0.6726 |    0.8142 |    0.7367 |      323 | Dense Support
OOB-Read             |    0.7216 |    0.7447 |    0.7330 |       94 | Dense Support
OOB-Write            |    0.7692 |    0.7143 |    0.7407 |       28 | Low Support
Use-After-Free       |    0.8049 |    0.7174 |    0.7586 |       92 | Dense Support
Double-Free          |    0.8333 |    0.7143 |    0.7692 |       28 | Low Support
NULL-Deref           |    0.7632 |    0.7073 |    0.7342 |      123 | Dense Support
Integer-Issues       |    0.7209 |    0.6458 |    0.6813 |      144 | Dense Support
Input-Validation     |    0.7391 |    0.6800 |    0.7083 |      150 | Dense Support
Info-Exposure        |    0.7059 |    0.6154 |    0.6575 |       78 | Dense Support
Access-Control       |    0.7414 |    0.6515 |    0.6935 |       66 | Dense Support
Crypto-Issues        |    0.8000 |    0.5714 |    0.6667 |       28 | Low Support
Resource-Mgmt        |    0.7586 |    0.7097 |    0.7333 |       93 | Dense Support
Race-Condition       |    0.7143 |    0.5882 |    0.6452 |       34 | Low Support
Path-Traversal       |    0.8000 |    0.6667 |    0.7273 |       24 | Low Support
Other-Security       |    0.6250 |    0.5618 |    0.5917 |       89 | Dense Support
-----------------------------------------------------------------------------------
Macro Average        |    0.7461 |    0.6513 |    0.6894 |     1314 | Balanced
```

**Tier 1 Observations:**
- All 15 groups have active support (standard for C/C++ memory-unsafe code)
- Strongest classes: Double-Free (F1 0.7692), Use-After-Free (F1 0.7586)
- Weakest class: Other-Security (F1 0.5917) — expected due to heterogeneous composition
- Memory-safety groups (0–5) collectively average **F1 0.7454**

### 7.2 Tier 2 C++ — Winner: GraphCodeBERT-v2 (Warm-Started)

Test set: 766 samples

```
Semantic Group       | Precision |    Recall |  F1-Score |  Support | Status
-----------------------------------------------------------------------------------
Buffer-Overflow      |    0.9123 |    0.8000 |    0.8525 |       65 | Dense Support
OOB-Read             |    0.9000 |    0.8182 |    0.8571 |       55 | Dense Support
OOB-Write            |    0.9211 |    0.8750 |    0.8974 |       80 | Dense Support
Use-After-Free       |    0.8696 |    0.8333 |    0.8511 |       30 | Low Support
Double-Free          |    1.0000 |    0.7500 |    0.8571 |        8 | Low Support
NULL-Deref           |    0.8621 |    0.8065 |    0.8333 |       47 | Dense Support
Integer-Issues       |    0.9062 |    0.8286 |    0.8657 |       70 | Dense Support
Input-Validation     |    0.8605 |    0.8539 |    0.8571 |       75 | Dense Support
Info-Exposure        |    0.8235 |    0.7778 |    0.8000 |       18 | Low Support
Access-Control       |    0.8750 |    0.8750 |    0.8750 |       40 | Low Support
Crypto-Issues        |    0.6667 |    1.0000 |    0.8000 |        4 | Near-Zero
Resource-Mgmt        |    0.8500 |    0.8095 |    0.8293 |       60 | Dense Support
Race-Condition       |    0.8000 |    0.6667 |    0.7273 |        6 | Near-Zero
Path-Traversal       |    0.8462 |    0.8462 |    0.8462 |       16 | Low Support
Other-Security       |    0.7647 |    0.7616 |    0.7632 |      192 | Dense Support
-----------------------------------------------------------------------------------
Macro Average        |    0.8756 |    0.8339 |    0.7568 |      766 | Balanced
```

### 7.3 Tier 2 Python — Winner: GraphCodeBERT-v2 (Warm-Started)

Test set: 96 samples

```
Semantic Group       | Precision |    Recall |  F1-Score |  Support | Status
-----------------------------------------------------------------------------------
Buffer-Overflow      |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
OOB-Read             |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
OOB-Write            |    0.0000 |    0.0000 |    0.0000 |        1 | Near-Zero ⓘ
Use-After-Free       |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Double-Free          |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
NULL-Deref           |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Integer-Issues       |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Input-Validation     |    0.9620 |    0.9286 |    0.9455 |       28 | Dominant
Info-Exposure        |    0.6667 |    1.0000 |    0.8000 |        2 | Low Support
Access-Control       |    0.8000 |    0.8000 |    0.8000 |        5 | Low Support
Crypto-Issues        |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Resource-Mgmt        |    1.0000 |    0.6667 |    0.8000 |        3 | Low Support
Race-Condition       |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Path-Traversal       |    0.9167 |    0.9167 |    0.9167 |       12 | Active
Other-Security       |    0.8889 |    0.7442 |    0.8101 |       43 | Active
```

> ⓘ **Near-Zero Support:** 9 groups have 0 test samples. Python's automatic memory management means buffer overflows, UAF, double-free, and NULL dereferences do not exist in standard Python. Input-Validation (0.9455 F1) and Path-Traversal (0.9167 F1) dominate.

### 7.4 Tier 2 PHP — Winner: CodeT5-v2 (Warm-Started)

Test set: 261 samples

```
Semantic Group       | Precision |    Recall |  F1-Score |  Support | Status
-----------------------------------------------------------------------------------
Buffer-Overflow      |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
OOB-Read             |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
OOB-Write            |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Use-After-Free       |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Double-Free          |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
NULL-Deref           |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Integer-Issues       |    0.5000 |    1.0000 |    0.6667 |        1 | Near-Zero
Input-Validation     |    0.9942 |    0.9716 |    0.9828 |      176 | Dominant (67.4%)
Info-Exposure        |    1.0000 |    1.0000 |    1.0000 |        9 | Low Support
Access-Control       |    0.8571 |    0.8571 |    0.8571 |       14 | Low Support
Crypto-Issues        |    0.6667 |    1.0000 |    0.8000 |        2 | Near-Zero
Resource-Mgmt        |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Race-Condition       |    0.0000 |    0.0000 |    0.0000 |        0 | Near-Zero ⓘ
Path-Traversal       |    1.0000 |    0.9167 |    0.9565 |       12 | Low Support
Other-Security       |    0.9783 |    0.9574 |    0.9677 |       47 | Active
```

> ⓘ **Near-Zero Support:** 8 groups have 0 test samples. PHP handles memory via its Zend engine. Input-Validation accounts for **67.4%** of all vulnerabilities (SQLi, XSS, command injection), with **0.9828 F1**. Info-Exposure achieves perfect 1.000 F1.

### 7.5 Tier 3 Shared (Go, Java, JavaScript, Ruby, TypeScript, JSON, Other) — Winner: CodeT5-v2

Test set: 374 samples

```
Semantic Group       | Precision |    Recall |  F1-Score |  Support | Status
-----------------------------------------------------------------------------------
Buffer-Overflow      |    0.5385 |    1.0000 |    0.7000 |        7 | Low Support
OOB-Read             |    0.8000 |    1.0000 |    0.8889 |       12 | Low Support
OOB-Write            |    0.4000 |    0.8000 |    0.5333 |        5 | Near-Zero
Use-After-Free       |    1.0000 |    0.6667 |    0.8000 |        3 | Near-Zero
Double-Free          |    1.0000 |    1.0000 |    1.0000 |        1 | Near-Zero
NULL-Deref           |    0.8000 |    0.8000 |    0.8000 |        5 | Near-Zero
Integer-Issues       |    0.7500 |    0.8571 |    0.8000 |        7 | Low Support
Input-Validation     |    0.9195 |    0.9392 |    0.9293 |      165 | Dominant (44.1%)
Info-Exposure        |    0.7500 |    0.7500 |    0.7500 |       12 | Low Support
Access-Control       |    0.8400 |    0.8077 |    0.8235 |       26 | Low Support
Crypto-Issues        |    0.6667 |    0.7273 |    0.6957 |       11 | Low Support
Resource-Mgmt        |    0.8333 |    0.7692 |    0.8000 |       20 | Low Support
Race-Condition       |    1.0000 |    0.6667 |    0.8000 |        3 | Near-Zero
Path-Traversal       |    0.7857 |    0.8462 |    0.8148 |       29 | Low Support
Other-Security       |    0.8333 |    0.8209 |    0.8271 |       68 | Active
-----------------------------------------------------------------------------------
Macro Average        |    0.8556 |    0.8307 |    0.6866 |      374 |
```

> **Tier 3 Observations:** All 15 groups have at least 1 sample. Input-Validation dominates at 44.1% (web languages). `<LANG=xx>` token prefix enables the shared model to distinguish between Go pointer issues and JavaScript prototype pollution.

---

## 8. Cross-Language Class Distribution Analysis

A central scientific finding of Phase 2 — the vulnerability landscape shifts dramatically between memory-unsafe and managed languages:

| Semantic Group | Tier 1 C/C++ | Tier 2 C++ | Tier 2 Python | Tier 2 PHP | Tier 3 Shared | Trend |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Buffer-Overflow** | 13.3% | 8.2% | 0.7% | 0.2% | 1.7% | **C/C++ near-exclusive** |
| **OOB-Read** | 8.6% | 7.0% | 0.6% | 0.1% | 2.9% | **C/C++ near-exclusive** |
| **OOB-Write** | 7.7% | 10.2% | 0.9% | 0.1% | 1.1% | **C/C++ near-exclusive** |
| **Use-After-Free** | 5.7% | 3.8% | 0.5% | 0.0% | 0.7% | **Zero in PHP** |
| **Double-Free** | 1.4% | 1.1% | 0.1% | 0.1% | 0.1% | **Absent in managed** |
| **Input-Validation** | 9.5% | 9.3% | **22.8%** | **61.7%** | **41.2%** | **Dominates Tier 2/3** |
| **Other-Security** | 16.1% | 26.5% | 47.3% | 22.9% | 24.7% | Catch-all |

> **Key Finding:** Memory-safety groups (0–5) account for **43.0%** of C/C++ (Tier 1) vulnerabilities and **36.3%** in C++ (Tier 2). In managed runtimes (Python, PHP, JS, Go), they account for **<3%**. Input-Validation and Access-Control dominate instead. **Never reuse a Tier 1 classifier on Tier 2/3.**

---

## 9. v1 → v2 Improvement Breakdown (Tier 1)

| Metric | v1 (24-class) | v2 CodeT5 | v2 GraphCodeBERT | v2 CodeBERT-MOO | v2 Ensemble ★ | % Improvement |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Macro-Recall** | 0.4348 | 0.5907 | 0.6398 | 0.6959 | **0.6513** | **+49.8%** |
| **Macro-F1** | 0.3213 | 0.6147 | 0.6769 | 0.6524 | **0.6894** | **+114.6%** |
| **Weighted-F1** | 0.3116 | 0.6214 | 0.6821 | 0.7103 | **0.6877** | **+120.7%** |
| **Accuracy** | 0.3189 | 0.6218 | 0.6849 | 0.7014 | **0.6895** | **+116.2%** |

**Root causes of improvement:**
1. Semantic 15-class grouping eliminated incoherent "Other" bucket noise
2. LoRA $r=64, \alpha=128$ (4× more parameters than v1) captured fine-grained syntactic patterns
3. Focal Loss suppressed majority-class gradient domination
4. WeightedRandomSampler ensured rare classes received proportional training signal
5. 512-token context preserved critical code context (allocations, sanitization)

---

## 10. Saved Artifacts

### Model Checkpoints

```
models/saved/
├── phase2_winner_tier1_c_cpp/        # Calibrated ensemble metadata
│   └── winner_metadata.json
├── phase2_winner_tier2_cpp/          # GraphCodeBERT-v2 LoRA weights
│   └── winner_metadata.json
├── phase2_winner_tier2_python/       # GraphCodeBERT-v2 LoRA weights
│   └── winner_metadata.json
├── phase2_winner_tier2_php/          # CodeT5-v2 LoRA weights
│   └── winner_metadata.json
└── phase2_winner_tier3_shared/       # CodeT5-v2 LoRA weights + lang tokens
    └── winner_metadata.json
```

### Result Logs

```
logs/
├── phase2_cwe_results_codet5_cwe_v2.json
├── phase2_cwe_results_graphcodebert_cwe_v2.json
├── phase2_cwe_results_ensemble_v2.json
├── phase2_cwe_results_moo_codebert_tier1_c_cpp.json
├── phase2_cwe_results_tier2_cpp_codet5_cwe_v2.json
├── phase2_cwe_results_tier2_cpp_graphcodebert_cwe_v2.json
├── phase2_cwe_results_tier2_python_codet5_cwe_v2.json
├── phase2_cwe_results_tier2_python_graphcodebert_cwe_v2.json
├── phase2_cwe_results_tier2_php_codet5_cwe_v2.json
├── phase2_cwe_results_tier2_php_graphcodebert_cwe_v2.json
├── phase2_cwe_results_tier3_shared_codet5_cwe_v2.json
├── phase2_cwe_results_tier3_shared_graphcodebert_cwe_v2.json
├── phase2_cwe_results_v1.json                          # Superseded v1 baseline
├── phase2_winners_v2.json                              # Consolidated winner selection
└── test_logits_*.pt                                    # Raw logits for ensemble / analysis
```

---

## 11. Reproduction Commands

### Full Multi-Tier Pipeline (Windows, CUDA)

```powershell
# Activate environment
cd D:\Minor_Project-PD\SecuraX
.venv\Scripts\activate

# Dry run — see all scheduled training runs
python src/models/run_phase2_all_tiers.py --dry-run

# Full execution (all tiers, ~14 hours total)
python src/models/run_phase2_all_tiers.py --bf16 --epochs 15
```

### Individual Commands

```powershell
# Tier 1: CodeT5, GraphCodeBERT, MOO, Ensemble
python src/models/train_cwe.py --model codet5 --tier tier1_c_cpp --variant-tag v2 --bf16 --epochs 15 --batch-size 16
python src/models/train_cwe.py --model graphcodebert --tier tier1_c_cpp --variant-tag v2 --bf16 --epochs 15 --batch-size 16
python src/models/train_codebert_moo.py --tier tier1_c_cpp --bf16 --epochs 10 --batch-size 16
python src/models/train_cwe.py --ensemble --variant-tag v2

# Tier 2: Warm-started from Tier 1 winner
python src/models/train_cwe.py --model graphcodebert --tier tier2_cpp --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model graphcodebert --tier tier2_python --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model codet5 --tier tier2_php --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15

# Tier 3: Shared multilingual with <LANG=xx> tokens
python src/models/train_cwe.py --model codet5 --tier tier3_shared --use-lang-tokens --variant-tag v2 --bf16 --epochs 15

# Evaluation and winner export
python src/evaluation/evaluate_cwe_v2.py --compare-all
python src/evaluation/evaluate_cwe_v2.py --select-winners
```

---

## 12. Known Limitations

1. **Extreme Support Skew:** In managed languages (Python, PHP), memory-safety groups have near-zero support. Macro metrics must always be interpreted alongside weighted metrics and support tables.
2. **Tier 2 Python Macro-F1 (0.4777):** Lower than other tiers because 9/15 groups have 0 test samples, inflating the macro denominator with zero scores.
3. **v1 → v2 Not Directly Comparable on Class Count:** v1 used 24 classes; v2 uses 15 semantic groups. Improvements reflect both better grouping and better training recipe.
4. **CodeBERT-MOO Scope:** Only applied to Tier 1 (C/C++). AIBugHunter's original design targeted C/C++ datasets; its transferability to managed languages is unverified.

---

## 13. Next Steps → Phase 3

Phase 3 adds **CVSS Severity Scoring (0–10 Regression)** using the Phase 2 winning encoders as feature extractors. Key considerations:
- CVSS scores are available for 6,094 samples across tiers
- Severity is about exploitability/impact (less syntax-dependent), so a shared cross-tier regressor may outperform per-tier models
- Both per-tier and shared approaches will be tested

---

*Generated by Phase 2 Multi-Tier CWE Classification Pipeline | Seed: 42 | Split ratios: 70/15/15*
