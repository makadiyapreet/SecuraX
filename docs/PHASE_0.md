# Phase 0 — Scoping & Setup

**Date:** September 2026  
**Status:** ✅ Complete

---

## Prerequisites Installed

### System-Level Tools

| Tool | Install Command (macOS) | Install Command (Linux) | Purpose |
|------|------------------------|------------------------|---------|
| Python 3.10+ | Pre-installed / `brew install python` | `sudo apt install python3` | Runtime |
| Git | `xcode-select --install` | `sudo apt install git` | Version control |
| Ollama | `brew install ollama` | `curl -fsSL https://ollama.com/install.sh \| sh` | Local LLM server |
| Cppcheck | `brew install cppcheck` | `sudo apt install cppcheck` | C/C++ static analysis |

### Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

**Key packages installed:**
- `torch` (PyTorch) — deep learning framework
- `transformers` — HuggingFace model loading
- `peft` — LoRA / parameter-efficient fine-tuning
- `datasets` — HuggingFace dataset utilities
- `scikit-learn` — evaluation metrics, stratified splitting
- `pandas`, `numpy` — data manipulation
- `streamlit` — web app framework
- `bandit` — Python security linter
- `matplotlib`, `seaborn` — visualization

All packages are free & open-source (MIT / Apache-2.0 / BSD / GPL).

---

## Dataset Exploration

### Dataset: BigVul (Fan et al., MSR 2020)

**Source:** [GitHub — MSR_20_Code_vulnerability_CSV_Dataset](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)

**Download command:**
```bash
python -m src.data.download_bigvul
```

### What the Data Exploration Script Reports

Run with:
```bash
python -m src.data.load_data
```

The script (`src/data/load_data.py`) prints the following:

1. **Total sample count** — number of rows in the CSV
2. **Vulnerability flag distribution** — count and percentage of vulnerable (1) vs. non-vulnerable (0) samples, plus the imbalance ratio
3. **CWE-id distribution** — unique CWE count, top-20 CWE-ids by frequency, and long-tail statistics
4. **Severity score format** — whether a CVSS column exists, its range (continuous 0–10 or categorical), and proposed binning into Low/Medium/High/Critical
5. **Programming languages** — detected language columns or inferred from file paths (BigVul is primarily C/C++)
6. **Code snippet columns** — which columns contain source code, average length, and a sample
7. **Stratified split creation** — 80/10/10 train/val/test split with per-split class balance verification

### Expected Findings (BigVul)

| Metric | Expected Value |
|--------|---------------|
| Total samples | ~188,000+ functions |
| Languages | C, C++ |
| Vulnerable % | ~5–10% (heavily imbalanced) |
| Unique CWE-ids | ~100–170 |
| Severity format | CVSS v2 score (0.0–10.0, continuous) if present; otherwise mapped from CWE |
| Key columns | `func_before`, `vul`, `cwe_id`, `cvss`, `project`, `commit_id` |

> **Note:** Exact numbers depend on the dataset version downloaded. Run the script for precise counts.

### Severity Score Decision

The BigVul dataset may include a `cvss` column with CVSS v2 base scores (continuous, 0.0–10.0). Our decision:

- **Keep as continuous** for regression-based severity scoring
- **Also bin into 4 categories** for classification experiments:

| Category | CVSS Range |
|----------|-----------|
| Low | 0.0 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

If no CVSS column is present, severity will be mapped from CWE-ids using NVD/CWE standard severity mappings in Phase 1.

---

## Verification Results

### ✅ Git Repository
- Initialized with sensible directory structure
- `.gitignore` covers Python, data, model checkpoints, and IDE files

### ✅ Python Environment
- `requirements.txt` created with all free/open-source packages
- All packages installable via `pip install -r requirements.txt`

### ⬜ Dataset Download & Exploration
- Download script ready: `python -m src.data.download_bigvul`
- Exploration script ready: `python -m src.data.load_data`
- **Requires user to run** (dataset is ~170 MB)

### ⬜ HuggingFace Model Verification
- Verification script ready: `python -m src.utils.verify_hf_model`
- Tests `microsoft/codebert-base` download, loading to MPS/CPU, and forward pass
- **Requires user to run** (model download ~440 MB)

### ⬜ Ollama Verification
- Verification script ready: `python -m src.utils.verify_ollama`
- **Requires Ollama installation first:** `brew install ollama`
- Tests server status, model pull, and test inference

### Compute Environment Detected

| Property | Value |
|----------|-------|
| Machine | Apple M2 |
| RAM | 8 GB |
| GPU | Apple MPS (Metal Performance Shaders) |
| Python | 3.13.1 |
| OS | macOS |

> **Note:** 8 GB RAM is tight for 7B LLMs. Mistral-7B requires ~4–5 GB in Q4 quantization. Fine-tuning with LoRA will need careful batch sizing. This is documented for Phase 1 planning.

---

## Train/Val/Test Split Strategy

**Confirmed strategy for ALL future phases:**

```
Split:   Train 80%  |  Val 10%  |  Test 10%
Seed:    42
Method:  sklearn.model_selection.train_test_split (two-stage)
Stratify: Composite key (vulnerability_flag + CWE-id)
```

**Details:**
1. Create composite stratification key: `"vul_{CWE-id}"` for vulnerable samples, `"non_vul"` for non-vulnerable
2. CWE classes with < 5 samples are grouped as `"vul_rare"` to prevent split failures
3. First split: 80% train vs 20% (val+test)
4. Second split: 50/50 within the 20% → 10% val, 10% test
5. Split indices saved to `data/processed/split_indices.npz`

---

## Open Questions & Decisions

| # | Question | Decision |
|---|----------|----------|
| 1 | Which severity score format? | Dual: keep continuous CVSS for regression + bin into 4 categories for classification |
| 2 | How to handle CWE classes with very few samples? | Group rare CWEs (< N samples) during training; exact threshold TBD in Phase 2 |
| 3 | Which encoder to use as primary? | Start with CodeBERT; compare with UnixCoder in Phase 1 |
| 4 | 8 GB RAM sufficient for Mistral-7B? | Use Q4 quantization via Ollama; batch size = 1 for inference |
| 5 | No ground-truth fixed code for refinement? | Person B will use prompting-based LLM refinement (no supervised fine-tuning for refinement task) |

---

## How to Run Everything at This Stage

```bash
# 1. Set up environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Install system tools (if not already done)
brew install ollama cppcheck

# 3. Download dataset
python -m src.data.download_bigvul

# 4. Run ALL Phase 0 checks
python run_phase0_checks.py

# 5. Or run individual checks:
python -m src.data.load_data           # Dataset exploration
python -m src.utils.verify_hf_model    # CodeBERT verification
python -m src.utils.verify_ollama      # Ollama verification
```

---

## What's Next (Phase 1)

Phase 1 will cover **Binary Vulnerability Detection**:
- Fine-tune CodeBERT/UnixCoder with a binary classification head
- Use LoRA for parameter-efficient fine-tuning
- Handle class imbalance (oversampling / weighted loss)
- Evaluate with Recall (primary), Precision, F1, AUROC
- Establish baseline performance
