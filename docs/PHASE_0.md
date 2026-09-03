# Phase 0 — Scoping & Setup

**Date:** September 2026
**Phase Goal:** Initialize the project, set up the development environment, explore the dataset, and verify that all required models can be loaded locally.

---

## Prerequisites Installed

### Python Environment

```bash
# Create virtual environment (Python 3.13)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
```

### Key Package Versions

| Package | Version | Purpose |
|---------|---------|---------|
| torch | ≥2.1.0 | Deep learning framework |
| transformers | ≥4.36.0 | HuggingFace model hub |
| peft | ≥0.7.0 | LoRA fine-tuning |
| bitsandbytes | ≥0.41.0 | 4-bit quantization (CUDA only) |
| accelerate | ≥0.25.0 | Device mapping |
| datasets | ≥2.16.0 | HuggingFace dataset loading |
| scikit-learn | ≥1.3.0 | Metrics & splitting |
| pandas | ≥2.1.0 | Data manipulation |
| streamlit | ≥1.29.0 | Web app UI (future) |
| bandit | ≥1.7.6 | Python static analysis |

### System-Level Tools

```bash
# Cppcheck — C/C++ static analysis
brew install cppcheck    # macOS
sudo apt install cppcheck  # Ubuntu

# Verify
cppcheck --version
```

---

## Dataset: BigVul (MSR 2020)

### Why BigVul?

The project requires **CWE-ids** for multi-class classification and **severity scores** for scoring. Among available free datasets:

| Dataset | Samples | CWE-ids | CVSS Scores | Languages | Verdict |
|---------|---------|---------|-------------|-----------|---------|
| **BigVul** | ~188K | ✅ Yes | ✅ Yes (CVSS v2) | C/C++ | ✅ **Primary** |
| Devign | ~27K | ❌ No | ❌ No | C/C++ | ❌ Binary only |
| CVEfixes | ~5K | ✅ Yes | ✅ Yes | Mixed | ✅ Cross-check |

**BigVul** was selected as the primary dataset because it's the only large-scale free dataset that contains all three required labels: vulnerability flag, CWE-id, and CVSS severity score.

### How to Download

```bash
# Automatic download
python src/data/download_bigvul.py

# Or manually from GitHub:
# https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset
# Download 'all_c_cpp_release2.0.csv' → data/raw/bigvul_all_c_cpp.csv
```

### How to Run Data Exploration

```bash
# From local CSV (after download)
python src/data/load_and_explore.py

# From HuggingFace Hub (alternative)
python src/data/load_and_explore.py --use-huggingface
```

### Data Exploration Results

### Data Exploration Results

Running `src/data/load_and_explore.py --use-huggingface` on the function-level BigVul dataset revealed:

1. **Basic Statistics:**
   - **Total samples:** 217,007 functions
   - **Pre-existing splits:** Train: 150,908 | Val: 33,049 | Test: 33,050
   - **Memory footprint:** ~562.5 MB

2. **Vulnerability Flag (VF) Distribution:**
   - Non-Vulnerable (`vul = 0`): **206,112** (95.0%)
   - Vulnerable (`vul = 1`): **10,895** (5.0%)
   - **Class imbalance ratio:** 18.9 : 1

3. **CWE-ID Class Distribution:**
   - **Unique CWE classes:** 90
   - **Top 10 CWE classes:**
     - CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer): 30,297 (14.0%)
     - CWE-20 (Improper Input Validation): 23,233 (10.7%)
     - CWE-399 (Resource Management Errors): 17,507 (8.1%)
     - CWE-264 (Permissions, Privileges, and Access Controls): 14,461 (6.7%)
     - CWE-416 (Use After Free): 11,073 (5.1%)
     - CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor): 9,760 (4.5%)
     - CWE-125 (Out-of-bounds Read): 9,035 (4.2%)
     - CWE-189 (Numeric Errors): 8,132 (3.7%)
     - CWE-362 (Concurrent Execution using Shared Resource with Improper Sync): 6,994 (3.2%)
     - CWE-476 (NULL Pointer Dereference): 5,383 (2.5%)

4. **Severity Score Analysis:**
   - **Format:** **Continuous (CVSS v2/v3 base scores, 0.0–10.0 scale)**
   - **Source:** Extracted from CVE metadata in BigVul (`data/raw/bigvul_all_c_cpp.csv`) & NVD
   - **Distribution summary (from CVE score analysis):**
     - Min: 0.00, Max: 10.00, Mean: 5.95, Median: 6.60, Std Dev: 1.93
     - None (0.0): 1.0% | Low (0.1–3.9): 6.3% | Medium (4.0–6.9): 58.3% | High (7.0–8.9): 26.7% | Critical (9.0–10.0): 7.7%

5. **Programming Languages:**
   - **C:** 213,919 (98.6%)
   - **C++ (CPP):** 3,088 (1.4%)

6. **Code Snippet Statistics (`func_before`):**
   - **Lines of Code (LOC):** Min: 2 | Max: 6,820 | Mean: 30.7 | Median: 14.0

7. **Stratified Split Verification (random seed = 42):**
   - 85 of 90 CWE classes meet the minimum sample threshold (≥7 samples)
   - **Train:** 122,698 samples (70.0%)
   - **Val:** 26,293 samples (15.0%)
   - **Test:** 26,293 samples (15.0%)

#### Severity Score Format Decision

**Decision: Use continuous CVSS scores (0.0–10.0)** as the severity target regression variable.

Rationale:
- Continuous regression allows fine-grained severity ranking and scoring
- Standard NVD categorical buckets (Low/Medium/High/Critical) can be derived at test/inference time directly from the predicted score
- Aligns with the target output table format (`Severity Score`)

---

## Model Verification

### How to Run

```bash
# Verify all models (encoders + LLMs)
python src/models/verify_models.py

# Verify encoders only (skip large LLMs)
python src/models/verify_models.py --skip-large
```

### Models Verified

| # | Model | Parameters | VRAM (est.) | Quantization | Purpose |
|---|-------|------------|-------------|--------------|---------|
| 1 | `Salesforce/codet5-base` | ~220M | ~0.9 GB | None (FP32) | Detection encoder |
| 2 | `microsoft/graphcodebert-base` | ~125M | ~0.5 GB | None (FP32) | Detection encoder |
| 3 | `mistralai/Mistral-7B-Instruct-v0.3` | ~7B | ~5 GB | 4-bit NF4 | Code refinement |
| 4 | `deepseek-ai/deepseek-coder-6.7b-instruct` | ~6.7B | ~4.5 GB | 4-bit NF4 | Code refinement |

### GPU Memory Notes

- **NVIDIA GPU (CUDA):** 4-bit quantization via bitsandbytes works natively. Minimum recommended: 8GB VRAM for LLMs.
- **Apple Silicon (MPS):** bitsandbytes 4-bit does **not** support MPS. Fallback options:
  1. Load in float16 (needs ~14GB unified memory for 7B models)
  2. Use smaller models: `deepseek-coder-1.3b-instruct` (~2.6GB in float16)
  3. Use GGUF format with `llama-cpp-python` for Metal-accelerated inference
- **CPU only:** Not recommended for LLMs. Encoders (CodeT5, GraphCodeBERT) work fine on CPU.

### Fallback Models

If the primary LLMs don't fit in GPU memory:

| Primary Model | Fallback | Parameters | VRAM |
|---------------|----------|------------|------|
| Mistral-7B-Instruct | `mistralai/Mistral-7B-Instruct-v0.1` | 7B | ~5 GB (4-bit) |
| DeepSeek-Coder-6.7B | `deepseek-ai/deepseek-coder-1.3b-instruct` | 1.3B | ~1 GB (4-bit) |

---

## Train/Val/Test Split Strategy

| Parameter | Value |
|-----------|-------|
| Method | Stratified by CWE-id |
| Train | 70% |
| Validation | 15% |
| Test | 15% |
| Random Seed | 42 |
| Min samples/class | 2 |
| Implementation | `sklearn.model_selection.train_test_split` with `stratify` |

**Rationale:** Stratification by CWE-id ensures that each vulnerability class is proportionally represented in all splits. This is critical because the CWE distribution is heavily imbalanced (some CWEs have thousands of samples, others have only a handful).

Classes with fewer than 2 samples cannot be stratified and are excluded from the split (they would be too rare to appear in all three subsets meaningfully).

---

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Primary dataset | BigVul (MSR 2020) | Only large-scale free dataset with CWE-ids + CVSS scores + vuln labels |
| Severity format | Continuous CVSS v2 (0–10) | More informative than categorical; buckets derivable at inference |
| Split strategy | 70/15/15 stratified by CWE-id | Standard ratio; stratification preserves class balance |
| Quantization | 4-bit NF4 via bitsandbytes | Required to fit 7B models in consumer GPU VRAM |
| MPS fallback | DeepSeek-Coder 1.3B + float16 | Fits in Apple Silicon unified memory |

## Open Questions

1. **Cross-dataset validation:** Should we also load CVEfixes for cross-checking/evaluation in Phase 1?
2. **CWE granularity:** Some CWEs are very rare (<5 samples). Should we merge them into an "Other" class or drop them entirely?
3. **Code truncation length:** What max token length should we use for CodeT5/GraphCodeBERT inputs? (512 is default, but some functions are longer)

---

## What's Next — Phase 1

Phase 1 will focus on **Data Preprocessing & Feature Engineering**:
- Clean and preprocess BigVul data (handle missing values, normalize CWE labels)
- Tokenize code snippets for CodeT5 and GraphCodeBERT
- Create the official train/val/test splits and save to `data/processed/`
- Implement a PyTorch Dataset class for efficient data loading
- Add data augmentation strategies for underrepresented CWE classes
