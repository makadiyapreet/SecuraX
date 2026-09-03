# Phase 0 — Scoping & Setup

**Date:** September 2026  
**Status:** ✅ Complete

---

## Prerequisites Installed

### System-Level Tools

| Tool | Version Installed | Install Command (macOS) | Purpose |
|------|-------------------|------------------------|---------|
| Python | 3.13.1 | Pre-installed | Runtime |
| Git | (pre-installed) | `xcode-select --install` | Version control |
| Ollama | 0.33.2 | `brew install ollama` | Local LLM server |
| Cppcheck | 2.21.0 | `brew install cppcheck` | C/C++ static analysis |

### Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Installed versions (key packages):**
- `torch` 2.14.0 (MPS backend for Apple M2)
- `transformers` 5.16.1
- `peft` 0.20.0
- `scikit-learn` 1.9.0
- `pandas` 3.0.5
- `streamlit` 1.63.0

All packages are free & open-source (MIT / Apache-2.0 / BSD / GPL).

---

## Data Exploration Results

### Dataset: BigVul (Fan et al., MSR 2020)

**Source:** [GitHub — MSR_20_Code_vulnerability_CSV_Dataset](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)  
**File:** `all_c_cpp_release2.0.csv` (53.8 MB)

### Key Findings

| Metric | Value |
|--------|-------|
| **Total samples** | **4,432** rows |
| **Columns** | 22 |
| **Languages** | C (4,203 = 94.8%), C++ (229 = 5.2%) |
| **Unique CWE-ids** | 91 (739 rows with null CWE) |
| **Severity (CVSS v2)** | Continuous 0.0–10.0, mean 5.95, median 6.60 |
| **Vulnerability flag** | ⚠️ **NOT PRESENT** — all 4,432 rows are vulnerable |
| **Inline code** | ⚠️ **NOT PRESENT** — metadata only |
| **Unique projects** | Multiple open-source projects (Linux kernel dominant) |

### ⚠️ Critical Finding 1: No Vulnerability Flag Column

This dataset version contains **only CVE records** — every row is a known vulnerability. There is no `vul` column and no non-vulnerable samples.

**Impact:** For binary vulnerability detection (Phase 1), we need non-vulnerable code samples.

**Resolved — Options for Phase 1:**
1. Use **Devign** dataset (balanced C/C++ vul/non-vul functions)
2. Use **BigVul with code** from HuggingFace (`benjis/bigvul`) which includes both vulnerable and non-vulnerable function pairs
3. Sample non-vulnerable functions from the same projects via git history
4. Combine with **CVEfixes** dataset

### ⚠️ Critical Finding 2: No Inline Code

The columns `version_before_fix` and `version_after_fix` contain **git commit hashes** (40-char SHA), not source code. The actual code must be fetched from git repositories using these commit references.

**Available reference columns:**
- `commit_id` — 4,429 non-null git commit SHAs
- `version_before_fix` — 4,432 commit hashes (vulnerable version)
- `version_after_fix` — 4,432 commit hashes (fixed version)
- `project` — source project name
- `ref_link` — reference URLs

### CWE-id Distribution (Top 20 of 91)

| CWE-ID | Count | % | Description |
|--------|-------|---|-------------|
| CWE-119 | 694 | 15.7% | Buffer overflow |
| CWE-20 | 445 | 10.0% | Improper input validation |
| CWE-125 | 365 | 8.2% | Out-of-bounds read |
| CWE-200 | 272 | 6.1% | Information exposure |
| CWE-264 | 266 | 6.0% | Permissions/privileges/access control |
| CWE-399 | 265 | 6.0% | Resource management errors |
| CWE-416 | 184 | 4.2% | Use after free |
| CWE-189 | 133 | 3.0% | Numeric errors |
| CWE-476 | 133 | 3.0% | NULL pointer dereference |
| CWE-190 | 109 | 2.5% | Integer overflow |
| CWE-362 | 99 | 2.2% | Race condition |
| CWE-787 | 72 | 1.6% | Out-of-bounds write |
| CWE-284 | 68 | 1.5% | Improper access control |
| CWE-79 | 44 | 1.0% | Cross-site scripting |
| CWE-254 | 34 | 0.8% | Security features |
| CWE-772 | 34 | 0.8% | Missing resource release |
| CWE-415 | 31 | 0.7% | Double free |
| CWE-400 | 27 | 0.6% | Uncontrolled resource consumption |
| CWE-369 | 27 | 0.6% | Divide by zero |
| CWE-17 | 24 | 0.5% | Code quality |
| *(other 71 CWEs)* | 367 | 8.3% | — |

### Severity Score (CVSS v2)

| Category | CVSS Range | Count | % of scored |
|----------|-----------|-------|------------|
| Low | 0.0 – 3.9 | 301 | 7.3% |
| **Medium** | **4.0 – 6.9** | **2,397** | **58.2%** |
| High | 7.0 – 8.9 | 1,098 | 26.7% |
| Critical | 9.0 – 10.0 | 318 | 7.7% |
| *(null)* | — | 318 | — |

**Format:** Continuous CVSS v2 base score (0.0–10.0)  
**Decision:** Keep continuous for regression + bin into 4 categories for classification.

---

## Verification Results

### ✅ Git Repository
- Initialized with project structure (21 files committed)

### ✅ Python Environment
- All packages installed via `pip install -r requirements.txt`
- PyTorch 2.14.0 with MPS backend

### ✅ Dataset Download & Exploration
- Downloaded: `all_c_cpp_release2.0.csv` (53.8 MB, 4,432 rows)
- Exploration script correctly identifies all columns and distributions
- Critical findings documented (no inline code, no non-vulnerable samples)

### ✅ HuggingFace Model (CodeBERT)
- `microsoft/codebert-base` downloaded successfully
- 124,645,632 parameters (498.6 MB @ FP32)
- Loaded on **MPS** (Apple M2 Metal GPU)
- Test inference passed: 68 tokens → torch.Size([1, 68, 768]) in 2,961 ms

### ⬜ Ollama — Needs Server Start
- Ollama CLI installed (v0.33.2) ✅
- Server not started during initial test run
- **Fix:** Run `brew services start ollama` then `python -m src.utils.verify_ollama`

### Compute Environment

| Property | Value |
|----------|-------|
| Machine | Apple M2 |
| RAM | 8 GB |
| GPU | Apple MPS (Metal Performance Shaders) |
| Python | 3.13.1 |
| PyTorch | 2.14.0 |
| OS | macOS (arm64) |

---

## Train/Val/Test Split Strategy

**Confirmed for ALL future phases:**

```
Split:   Train 80%  |  Val 10%  |  Test 10%
Seed:    42
Method:  sklearn train_test_split (two-stage)
Stratify: CWE-id (rare CWEs with <3 samples grouped)
```

| Split | Samples | % |
|-------|---------|---|
| Train | 3,545 | 80.0% |
| Val | 443 | 10.0% |
| Test | 444 | 10.0% |
| **Total** | **4,432** | **100%** |

Split indices saved to `data/processed/split_indices.npz`.

---

## Decisions Made

| # | Question | Decision |
|---|----------|----------|
| 1 | Severity score format? | **Dual:** continuous CVSS for regression + 4-category bins for classification |
| 2 | Dataset has no inline code? | **Use alternative source for Phase 1** — either BigVul-with-code from HuggingFace, Devign dataset, or fetch code via commit hashes |
| 3 | Dataset has no non-vulnerable samples? | **Need to supplement** — Devign or BigVul-full version includes both |
| 4 | Split stratification key? | **CWE-id** (since all samples are vulnerable, can't stratify by vul flag) |
| 5 | Which encoder first? | Start with CodeBERT; compare UnixCoder in Phase 1 |
| 6 | 8 GB RAM for 7B LLMs? | Use Q4 quantization via Ollama; batch size = 1 |
| 7 | This metadata CSV still useful? | **YES** — use for CWE→severity mapping table, project context, and cross-referencing |

---

## How to Run Everything at This Stage

```bash
# 1. Set up environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Install system tools
brew install ollama cppcheck

# 3. Download dataset
python -m src.data.download_bigvul

# 4. Explore dataset
python -m src.data.load_data

# 5. Start Ollama and verify
brew services start ollama
python -m src.utils.verify_ollama

# 6. Verify HuggingFace model
python -m src.utils.verify_hf_model

# 7. Run ALL checks
python run_phase0_checks.py
```

---

## What's Next (Phase 1)

Phase 1 will address the two critical gaps before starting model training:

1. **Obtain a dataset with actual code + vulnerability labels:**
   - Option A: BigVul processed version with `func_before`/`func_after` columns
   - Option B: Devign dataset (balanced binary classification, C functions)
   - Option C: Fetch code from git repos using commit hashes from this metadata CSV

2. **Binary Vulnerability Detection:**
   - Fine-tune CodeBERT/UnixCoder with a binary classification head
   - Use LoRA for parameter-efficient fine-tuning on M2
   - Handle class imbalance (oversampling / weighted loss)
   - Evaluate: Recall (primary), Precision, F1, AUROC
