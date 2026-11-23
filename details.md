# SecuraX — Complete Project Details

> **Everything implemented in this project, explained from scratch.**

---

## Table of Contents

1. [What is this project?](#1-what-is-this-project)
2. [Why does this project exist?](#2-why-does-this-project-exist)
3. [What dataset is used?](#3-what-dataset-is-used)
4. [What AI models are used?](#4-what-ai-models-are-used)
5. [How does LoRA work?](#5-how-does-lora-work-and-why-do-we-use-it)
6. [Project roadmap — all phases](#6-project-roadmap--all-phases)
7. [Phase 0 — Setup & exploration](#7-phase-0--setup--exploration-completed)
8. [Phase 1 — Binary vulnerability detection](#8-phase-1--binary-vulnerability-detection-completed)
9. [Phase 2 — CWE multi-class classification](#9-phase-2--cwe-multi-class-classification-completed)
10. [All source files explained](#10-all-source-files-explained)
11. [All model checkpoints explained](#11-all-model-checkpoints-explained)
12. [All result files explained](#12-all-result-files-explained)
13. [How to run everything from scratch](#13-how-to-run-everything-from-scratch)
14. [Known issues & fixes applied](#14-known-issues--fixes-applied)
15. [What's left to do](#15-whats-left-to-do)

---

## 1. What is this project?

**SecuraX** is an AI-based system that takes a piece of source code (C/C++) and does **four things**:

1. **Detects** if the code has a security vulnerability (yes/no)
2. **Classifies** what *type* of vulnerability it is (e.g., buffer overflow, use-after-free, etc.) using CWE-id codes
3. **Scores** how severe the vulnerability is on a 0–10 scale (CVSS score)
4. **Fixes** the code by suggesting a patched version using a Large Language Model (LLM)

**Example output:**

| Language | Code Snippet | Vulnerable? | CWE Type | Severity | Fixed Code |
|----------|-------------|-------------|----------|----------|------------|
| C | `gets(buf)` | Yes (1) | CWE-119 (Buffer Overflow) | 7.5 / 10 | `fgets(buf, sizeof(buf), stdin)` |

**Hard constraint:** Everything in this project is **100% free and open-source**. No paid APIs (no OpenAI, no Google Cloud). All models run locally on your own machine.

---

## 2. Why does this project exist?

Software vulnerabilities cause billions of dollars in damage every year. Current vulnerability detection is mostly manual code review or rule-based static analysis tools (like Cppcheck or Bandit). These tools:
- Miss many types of vulnerabilities (high false negatives)
- Can't classify *what type* of vulnerability it is
- Can't score *how dangerous* it is
- Can't *fix* the code automatically

This project uses **AI/deep learning** to do all four tasks — detect, classify, score, and fix — using pre-trained code understanding models that have been fine-tuned on real-world vulnerability data.

---

## 3. What dataset is used?

### BigVul (MSR 2020)

We use **BigVul**, a large-scale dataset of C/C++ functions from real-world open-source projects, each labeled with whether they are vulnerable and what type of vulnerability they contain.

| Property | Value |
|----------|-------|
| **Name** | BigVul (MSR 2020 dataset) |
| **Source** | [GitHub](https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset) / [HuggingFace](https://huggingface.co/datasets/benjis/bigvul) |
| **Total samples** | **217,007** C/C++ functions |
| **Vulnerable samples** | **10,895** (5.0%) |
| **Non-vulnerable samples** | **206,112** (95.0%) |
| **Unique CWE classes** | 84 vulnerability types |
| **Has CVSS scores** | Yes (0.0–10.0 scale) |
| **Languages** | C (98.6%), C++ (1.4%) |
| **Code length** | 2–6,820 lines per function (median: 14 lines) |

**Why BigVul?** It's the *only* large-scale free dataset that has all three labels we need:
- ✅ Vulnerability flag (vulnerable or not)
- ✅ CWE-id (what type of vulnerability)
- ✅ CVSS severity score (how dangerous)

### Key data challenge: Severe class imbalance

- **Binary:** Only 5% of samples are vulnerable (95% are safe) — ratio of 18.9:1
- **CWE classes:** The top CWE class (CWE-119, buffer overflow) has 2,139 samples (24.4%), while 27 classes have fewer than 5 samples each

This imbalance is the biggest challenge in the project and affects model accuracy significantly.

---

## 4. What AI models are used?

### Encoder Models (for detection, classification, scoring)

These models *read* code and produce a numerical representation (embedding) that captures the code's meaning. We then add a "classification head" (a simple neural network layer) on top.

| Model | Creator | Parameters | What it does |
|-------|---------|------------|-------------|
| **CodeT5-base** | Salesforce | ~110 million | A Transformer encoder pre-trained on millions of code snippets. Understands code structure, syntax, and patterns across 8 programming languages. **This is our primary model (Phase 1 winner).** |
| **GraphCodeBERT-base** | Microsoft | ~125 million | Similar to CodeT5 but based on RoBERTa architecture. Also pre-trained on code. **Tested in Phase 1 but lost to CodeT5.** |

### LLM Models (for code fixing — future phases)

These models *generate* text/code. They will be used to produce fixed versions of vulnerable code.

| Model | Creator | Parameters | Purpose |
|-------|---------|------------|---------|
| Mistral-7B-Instruct | Mistral AI | 7 billion | Code refinement (runs in 4-bit quantization to fit in GPU memory) |
| DeepSeek-Coder-6.7B-Instruct | DeepSeek | 6.7 billion | Code refinement (runs in 4-bit quantization) |

---

## 5. How does LoRA work and why do we use it?

**Problem:** CodeT5-base has 110 million parameters. Fine-tuning all of them requires massive GPU memory and risks overfitting on our relatively small dataset.

**Solution: LoRA (Low-Rank Adaptation)**

LoRA is a technique that *freezes* the original model weights and inserts tiny trainable "adapter" matrices into the attention layers. Instead of updating 110 million parameters, we only train about **591,000 parameters (0.54%)**.

```
Original model:     110,199,940 parameters (FROZEN — not changed)
LoRA adapters:          591,362 parameters (TRAINED — these learn the new task)
Total trainable:              0.54% of the model
```

**Our LoRA settings:**
- **Rank (r):** 16 — controls adapter size (higher = more capacity, more memory)
- **Alpha (α):** 32 — scaling factor (usually 2× rank)
- **Target modules:** `["q", "v"]` — only the query and value attention projections are adapted
- **Dropout:** 0.1 — regularization to prevent overfitting

**Benefits:**
- ✅ 200× fewer trainable parameters
- ✅ Training fits in 8GB GPU memory
- ✅ Prevents overfitting on small datasets
- ✅ Saved checkpoint is only ~2.3 MB (instead of ~850 MB for the full model)

---

## 6. Project Roadmap — All Phases

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| **0** | Scoping & Setup | ✅ **Complete** | Set up repo, install dependencies, explore dataset, verify models load |
| **1** | Binary Detection | ✅ **Complete** | Train models to detect "vulnerable vs. non-vulnerable" |
| **2** | CWE Classification | ✅ **Complete** | Train model to classify the vulnerability type (24 CWE classes) |
| **3** | Severity Scoring | 🔲 Not started | Predict CVSS severity score (0–10 regression) |
| **4** | LLM Code Refinement | 🔲 Not started | Use Mistral/DeepSeek to generate fixed code |
| **5** | Streamlit App | 🔲 Not started | Build a web UI to demo the full pipeline |
| **6** | Final Report | 🔲 Not started | Write evaluation report and documentation |

---

## 7. Phase 0 — Setup & Exploration (COMPLETED)

**Goal:** Set up the project structure, install all dependencies, explore the dataset, and verify that all models can load.

### What was done:

1. **Created the project structure** — organized folders for `src/`, `models/`, `data/`, `docs/`, `logs/`, `app/`
2. **Set up Python virtual environment** — `.venv` with all dependencies from `requirements.txt`
3. **Explored the BigVul dataset** — analyzed class distributions, severity scores, code lengths
4. **Verified all 4 models load** — CodeT5, GraphCodeBERT, Mistral-7B, DeepSeek-Coder
5. **Defined split strategy** — 70% train / 15% validation / 15% test, stratified by CWE-id, seed=42
6. **Decided on severity format** — use continuous CVSS scores (0–10) instead of categorical buckets

### Key findings from data exploration:

| Finding | Value |
|---------|-------|
| Total samples | 217,007 |
| Vulnerability ratio | 5.0% vulnerable / 95.0% non-vulnerable |
| CWE classes | 90 unique types |
| Severity range | 0.0–10.0 (mean: 5.95, median: 6.60) |
| Code length | median 14 lines, mean 30.7 lines, max 6,820 lines |

### Output files:
- `docs/PHASE_0.md` — full documentation
- `requirements.txt` — all Python dependencies

---

## 8. Phase 1 — Binary Vulnerability Detection (COMPLETED)

**Goal:** Train two AI models (CodeT5 and GraphCodeBERT) to answer: *"Is this code vulnerable or not?"* Then pick the better one.

### How it works:

```
Input:  C/C++ function source code (as text)
   ↓
[Tokenizer] Convert text to numbers (token IDs)
   ↓
[CodeT5/GraphCodeBERT Encoder] Process tokens → hidden representation (768-dim vector)
   ↓
[Classification Head] Linear layer: 768 → 2 (vulnerable vs. non-vulnerable)
   ↓
Output: "Vulnerable" (1) or "Non-vulnerable" (0) + confidence %
```

### Training details:

| Setting | Value |
|---------|-------|
| **Dataset** | 20,000 samples (stratified subsample from 217K) |
| **Split** | Train: 14,000 / Val: 3,000 / Test: 3,000 |
| **Class ratio** | 5% vulnerable, 95% non-vulnerable |
| **Models trained** | CodeT5-base + LoRA, GraphCodeBERT-base + LoRA |
| **Epochs** | 5 (both models ran all 5, no early stopping triggered) |
| **Batch size** | 8 (effective 32 with gradient accumulation of 4) |
| **Learning rate** | 0.0002 (2e-4) |
| **Optimizer** | AdamW (weight decay 0.01) |
| **Scheduler** | Cosine Annealing (gradual LR decrease) |
| **Max token length** | 256 tokens (longer code is truncated) |
| **Device** | Apple Silicon MPS (Metal Performance Shaders) |
| **Training time** | ~67 min (CodeT5) + ~59 min (GraphCodeBERT) = ~126 min total |

### Results — Model Comparison:

| Metric | CodeT5 | GraphCodeBERT | Winner |
|--------|--------|---------------|--------|
| **Recall ★** | **0.5667** | 0.5533 | **CodeT5** |
| Precision | **0.8586** | 0.8469 | **CodeT5** |
| F1 Score | **0.6827** | 0.6694 | **CodeT5** |
| AUROC | **0.9087** | 0.9062 | **CodeT5** |
| Accuracy | **0.9737** | 0.9727 | **CodeT5** |
| Loss ↓ | **0.1068** | 0.1174 | **CodeT5** |

### What these metrics mean:

- **Recall (0.5667):** Of all truly vulnerable functions, the model correctly catches **56.67%**. This is the *primary metric* because missing a real vulnerability is dangerous.
- **Precision (0.8586):** Of all functions the model *flagged* as vulnerable, **85.86%** actually were. Few false alarms.
- **F1 Score (0.6827):** Harmonic mean of recall and precision. Balances both.
- **AUROC (0.9087):** The model's ability to rank vulnerable code higher than non-vulnerable code across all thresholds. 0.5 = random, 1.0 = perfect.
- **Accuracy (0.9737):** 97.37% of all predictions were correct. (High because 95% of data is non-vulnerable — even predicting "safe" always gives 95% accuracy.)

### 🏆 Winner: CodeT5

CodeT5 won on **all 6 metrics**. It was selected as the backbone for all future phases.

### CodeT5 Training Progress (epoch by epoch):

| Epoch | Train Loss | Val Loss | Val Recall | Val Precision | Val F1 | Time |
|-------|-----------|----------|------------|---------------|--------|------|
| 1 | 0.1825 | 0.1255 | 0.5629 | 0.6028 | 0.5822 | 13.6 min |
| 2 | 0.1001 | 0.1075 | 0.5563 | 0.7850 | 0.6512 | 13.4 min |
| 3 | 0.0894 | 0.0972 | 0.5497 | 0.8058 | 0.6535 | 13.4 min |
| 4 | 0.0825 | 0.1006 | 0.5762 | 0.7699 | 0.6591 | 13.5 min |
| 5 | 0.0784 | 0.0973 | 0.5894 | 0.7607 | **0.6642** | 13.7 min |

### Inference demo:

```bash
python src/evaluation/evaluate_binary.py --predict --model codet5 \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

Output:
```
Prediction:  NON-VULNERABLE
Confidence:  96.22%
```

> **Note:** The model incorrectly classified `gets()` (a classic buffer overflow) as non-vulnerable. This shows the limitation of the 56.67% recall — the model misses some real vulnerabilities, especially short snippets without surrounding context.

### Source files:
- `src/data/dataset.py` — binary dataset and DataLoader factory
- `src/models/train_binary.py` — training script (CodeT5 + GraphCodeBERT)
- `src/evaluation/evaluate_binary.py` — evaluation, comparison, and inference

### Saved models:
- `models/saved/codet5_binary_best/` — CodeT5 LoRA checkpoint (~2.3 MB)
- `models/saved/graphcodebert_binary_best/` — GraphCodeBERT LoRA checkpoint (~4.5 MB)
- `models/saved/phase1_winner/` — Copy of CodeT5 (the winner)

---

## 9. Phase 2 — CWE Multi-Class Classification (COMPLETED)

**Goal:** Given code that is *already known to be vulnerable*, classify **which type** of vulnerability it is (CWE-id).

### What is a CWE?

CWE stands for **Common Weakness Enumeration**. It's a standardized list of software vulnerability types maintained by MITRE. Examples:

| CWE | Name | Example |
|-----|------|---------|
| CWE-119 | Buffer Overflow | Writing past the end of an array |
| CWE-416 | Use After Free | Using memory after it's been freed |
| CWE-476 | NULL Pointer Dereference | Accessing a null pointer |
| CWE-200 | Information Exposure | Leaking sensitive data |
| CWE-362 | Race Condition | Two threads accessing shared data unsafely |
| CWE-190 | Integer Overflow | Integer arithmetic that wraps around |

### The class imbalance problem:

The dataset has **84 unique CWE classes**, but the distribution is extremely uneven:

```
CWE-119 (Buffer Overflow):     2,139 samples  (24.4%)  ████████████████████████
CWE-20 (Input Validation):     1,136 samples  (13.0%)  █████████████
CWE-399 (Resource Management):   742 samples   (8.5%)  ████████
CWE-125 (Out-of-bounds Read):    630 samples   (7.2%)  ███████
...
CWE-668 (Resource Exposure):       1 sample    (0.01%) ▏
CWE-502 (Deserialization):         1 sample    (0.01%) ▏
CWE-352 (CSRF):                    1 sample    (0.01%) ▏
```

You **cannot** train a model to recognize a vulnerability type from just 1 sample. So we handled this in two ways:

### Imbalance mitigation strategy (two-pronged):

**1. Rare-class bucketing ("Other" class):**
- CWE classes with **< 50 samples** are merged into a single "Other" class
- This reduces 84 classes → **24 classes** (23 individual CWEs + 1 "Other" bucket containing 61 rare types)
- The threshold of 50 ensures at least ~35 training samples per class after splitting

**2. Weighted loss function:**
- We use **inverse-frequency weighted CrossEntropyLoss**
- Rare classes get higher loss weights so the model pays more attention to them
- Weights are clamped at 10× maximum to prevent extreme values
- Formula: `weight = total_samples / (num_classes × class_count)`

### The 24 final classes:

| # | CWE | Description | Samples |
|---|-----|-------------|---------|
| 0 | CWE-119 | Buffer Overflow | 2,139 |
| 1 | CWE-125 | Out-of-bounds Read | 630 |
| 2 | CWE-17 | Code | 53 |
| 3 | CWE-189 | Numeric Errors | 341 |
| 4 | CWE-19 | Data Processing | 60 |
| 5 | CWE-190 | Integer Overflow | 311 |
| 6 | CWE-20 | Input Validation | 1,136 |
| 7 | CWE-200 | Information Exposure | 508 |
| 8 | CWE-254 | Security Features | 125 |
| 9 | CWE-264 | Permissions/Privileges | 493 |
| 10 | CWE-284 | Access Control | 169 |
| 11 | CWE-310 | Cryptographic Issues | 88 |
| 12 | CWE-362 | Race Condition | 266 |
| 13 | CWE-399 | Resource Management | 742 |
| 14 | CWE-404 | Resource Close/Release | 64 |
| 15 | CWE-415 | Double Free | 78 |
| 16 | CWE-416 | Use After Free | 323 |
| 17 | CWE-476 | NULL Pointer Dereference | 225 |
| 18 | CWE-59 | Link Following | 55 |
| 19 | CWE-732 | Incorrect Permissions | 65 |
| 20 | CWE-772 | Resource Leak | 52 |
| 21 | CWE-787 | Out-of-bounds Write | 191 |
| 22 | CWE-79 | Cross-Site Scripting (XSS) | 53 |
| 23 | Other | 61 rare CWE types combined | 593 |

### Architecture (how it works):

```
Input:  Vulnerable C/C++ function code
   ↓
[CodeT5 Tokenizer] Convert to token IDs (max 256 tokens)
   ↓
[CodeT5 Encoder + LoRA] Process tokens → 768-dimensional hidden representation
   ↓
[Mean Pooling] Average all token embeddings → single 768-dim vector
   ↓
[Dropout 0.1] Regularization
   ↓
[Linear Layer] 768 → 24 (one score per CWE class)
   ↓
[Softmax] Convert scores to probabilities
   ↓
Output: Top CWE predictions with confidence percentages
```

**Important:** This model uses **fresh LoRA adapters** (not reusing Phase 1's binary detection adapters). Phase 1 learned "is it vulnerable?", but Phase 2 needs to learn "what *kind* of vulnerability?" — a completely different task. Reusing Phase 1's LoRA would cause negative transfer.

### Training details:

| Setting | Value |
|---------|-------|
| **Dataset** | 8,760 vulnerable samples with valid CWE IDs |
| **Split** | Train: 6,132 / Val: 1,314 / Test: 1,314 (stratified by CWE) |
| **Num classes** | 24 |
| **Epochs trained** | 10 (best checkpoint at epoch 10) |
| **Batch size** | 8 (effective 32 with grad_accum=4) |
| **Learning rate** | 2e-4 |
| **Optimizer** | AdamW (weight_decay=0.01) |
| **Loss function** | Weighted CrossEntropyLoss (inverse-frequency, clamped 10×) |
| **Early stopping** | Patience=3 (by validation macro-F1), did not trigger |
| **Device** | Apple Silicon MPS |

### Test Set Results:

| Metric | Value | What it means |
|--------|-------|---------------|
| **Macro-Recall** | **0.4348** | On average, each CWE class gets 43.5% of its samples correctly identified |
| **Macro-F1** | **0.3213** | Average F1 score across all 24 classes (treats all classes equally) |
| Weighted-F1 | 0.3116 | F1 weighted by class size (larger classes matter more) |
| Accuracy | 0.3189 | 31.9% of individual predictions are exactly correct |
| Loss | 2.1528 | Cross-entropy loss on test set |

### Per-class performance:

| CWE | What it is | Precision | Recall | F1 | Test Samples | Correct |
|-----|-----------|-----------|--------|----|-------------|---------|
| CWE-119 | Buffer Overflow | 0.624 | 0.321 | 0.424 | 321 | 32.1% |
| CWE-125 | Out-of-bounds Read | 0.365 | 0.532 | 0.433 | 94 | 53.2% |
| CWE-190 | Integer Overflow | 0.333 | 0.532 | 0.410 | 47 | 53.2% |
| CWE-415 | **Double Free** | **0.450** | **0.750** | **0.563** | 12 | **75.0%** |
| CWE-310 | Crypto Issues | 0.323 | 0.769 | 0.455 | 13 | 76.9% |
| CWE-732 | Permissions | 0.368 | 0.778 | 0.500 | 9 | 77.8% |
| CWE-404 | Resource Close | 0.276 | 0.889 | 0.421 | 9 | **88.9%** |
| CWE-416 | **Use After Free** | **0.122** | **0.102** | **0.111** | 49 | **10.2%** |
| CWE-200 | **Info Exposure** | **0.235** | **0.105** | **0.146** | 76 | **10.5%** |
| Other | **61 rare CWEs** | **0.200** | **0.090** | **0.124** | 89 | **9.0%** |

### Worst-performing classes and why:

| Class | F1 | Why it fails |
|-------|-----|-------------|
| **CWE-416** (Use After Free) | 0.111 | Looks very similar to CWE-119 (buffer overflow) and CWE-125 (out-of-bounds read) at the code level. All involve pointer/memory access. The model can't tell them apart because distinguishing requires understanding the *temporal sequence* (alloc → free → use), which is hard to capture. |
| **Other** (61 rare CWEs) | 0.124 | A catch-all bucket of 61 completely different vulnerability types. There's no single pattern to learn — it's just "everything else." Inherently unlearnable as a coherent class. |
| **CWE-200** (Info Exposure) | 0.146 | This is a *semantic* vulnerability — it depends on *what data* is being exposed, not on code syntax. The model sees code patterns, but can't know if the data being leaked is "sensitive" or not. |

### Inference demo:

```bash
python src/evaluation/evaluate_cwe.py --predict \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

Output:
```
Top-3 CWE Predictions:
  1. CWE-119         13.51%    ← Buffer Overflow (correct!)
  2. CWE-264          9.52%
  3. Other            8.82%
```

### Source files:
- `src/data/dataset_cwe.py` — CWE dataset, label mapping, DataLoaders
- `src/models/train_cwe.py` — CWE training script with weighted loss
- `src/evaluation/evaluate_cwe.py` — evaluation and inference

### Saved model:
- `models/saved/codet5_cwe_best/` — CWE classifier LoRA checkpoint (~2.3 MB)

---

## 10. All Source Files Explained

| File | Purpose |
|------|---------|
| **`src/data/dataset.py`** | PyTorch Dataset for **binary** classification. Loads BigVul, tokenizes code for CodeT5/GraphCodeBERT, creates stratified train/val/test splits, builds DataLoaders. |
| **`src/data/dataset_cwe.py`** | PyTorch Dataset for **CWE** classification. Filters to vulnerable-only samples, builds CWE label map (with rare-class bucketing), creates stratified splits, builds DataLoaders. |
| **`src/data/download_bigvul.py`** | Downloads the BigVul dataset from GitHub. |
| **`src/data/load_and_explore.py`** | Explores the dataset: prints statistics, class distributions, severity scores. |
| **`src/models/train_binary.py`** | Phase 1 training script. Defines `CodeT5BinaryClassifier` (encoder + 2-class head), LoRA integration, training loop with early stopping, evaluation, checkpoint saving. Also handles `GraphCodeBERT` via `AutoModelForSequenceClassification`. |
| **`src/models/train_cwe.py`** | Phase 2 training script. Defines `CodeT5CWEClassifier` (encoder + 24-class head), inverse-frequency class weight computation, weighted CrossEntropyLoss, training loop, confusion matrix generation, worst-class analysis. |
| **`src/models/verify_models.py`** | Verifies that all 4 models (2 encoders + 2 LLMs) can be loaded. |
| **`src/evaluation/evaluate_binary.py`** | Phase 1 evaluation. Compares CodeT5 vs GraphCodeBERT, selects winner, copies to `phase1_winner/`, supports `--predict` for inference on a snippet. |
| **`src/evaluation/evaluate_cwe.py`** | Phase 2 evaluation. Displays per-class metrics table, confusion matrix diagonal, worst-class analysis, supports `--predict` for CWE inference on a snippet. |

---

## 11. All Model Checkpoints Explained

| Checkpoint | Phase | Task | Size | Description |
|------------|-------|------|------|-------------|
| `models/pretrained/codet5-base/` | — | — | ~850 MB | Base CodeT5 weights downloaded from HuggingFace (stored locally to avoid SSL issues) |
| `models/pretrained/graphcodebert-base/` | — | — | ~500 MB | Base GraphCodeBERT weights |
| `models/saved/codet5_binary_best/` | 1 | Binary detection | ~2.3 MB | CodeT5 + LoRA adapters for vulnerable/non-vulnerable classification |
| `models/saved/graphcodebert_binary_best/` | 1 | Binary detection | ~4.5 MB | GraphCodeBERT + LoRA adapters (lost to CodeT5) |
| `models/saved/phase1_winner/` | 1 | Binary detection | ~2.3 MB | Copy of `codet5_binary_best` (the winning model) |
| `models/saved/codet5_cwe_best/` | 2 | CWE classification | ~2.3 MB | CodeT5 + LoRA adapters for 24-class CWE classification |

> **Why are checkpoints only ~2.3 MB?** Because we use LoRA. Only the tiny adapter weights are saved, not the full 850 MB base model. To use a checkpoint, you load the base model + apply the adapter on top.

---

## 12. All Result Files Explained

### In `logs/`:

| File | Contents |
|------|----------|
| `train_codet5_binary.log` | Full CodeT5 Phase 1 training log (every batch, every epoch) |
| `train_graphcodebert_binary.log` | Full GraphCodeBERT Phase 1 training log |
| `train_cwe.log` | Full Phase 2 CWE training log |
| `phase1_codet5_results.json` | CodeT5 test metrics + full training history (5 epochs) |
| `phase1_graphcodebert_results.json` | GraphCodeBERT test metrics + full training history (5 epochs) |
| `phase1_comparison.json` | Side-by-side comparison of both models + winner selection |
| `phase2_cwe_results.json` | CWE test metrics, per-class report, full 24×24 confusion matrix, worst classes |
| `cwe_label_map.json` | Mapping of CWE-id string → class index (e.g., "CWE-119" → 0) |

### In `results/` (organized copies):

| File | Description |
|------|-------------|
| `results/README.md` | Overview of all models and quick results |
| `results/phase1_binary_detection/SUMMARY.md` | Human-readable Phase 1 summary |
| `results/phase1_binary_detection/codet5_results.json` | CodeT5 binary detection results |
| `results/phase1_binary_detection/graphcodebert_results.json` | GraphCodeBERT binary detection results |
| `results/phase1_binary_detection/comparison.json` | Model comparison + winner |
| `results/phase2_cwe_classification/SUMMARY.md` | Human-readable Phase 2 summary |
| `results/phase2_cwe_classification/cwe_results.json` | CWE classification results + confusion matrix |
| `results/phase2_cwe_classification/cwe_label_map.json` | CWE label mapping |

---

## 13. How to Run Everything from Scratch

### 1. Environment setup

```bash
cd "Minor Project"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Download pretrained model weights locally

```bash
# CodeT5-base (~850MB)
mkdir -p models/pretrained/codet5-base
curl -L "https://huggingface.co/Salesforce/codet5-base/resolve/main/pytorch_model.bin" \
  -o models/pretrained/codet5-base/pytorch_model.bin
curl -L "https://huggingface.co/Salesforce/codet5-base/resolve/main/config.json" \
  -o models/pretrained/codet5-base/config.json

# GraphCodeBERT-base (~500MB)
mkdir -p models/pretrained/graphcodebert-base
curl -L "https://huggingface.co/microsoft/graphcodebert-base/resolve/main/pytorch_model.bin" \
  -o models/pretrained/graphcodebert-base/pytorch_model.bin
curl -L "https://huggingface.co/microsoft/graphcodebert-base/resolve/main/config.json" \
  -o models/pretrained/graphcodebert-base/config.json
```

### 3. Phase 1 — Train binary detectors

```bash
# Train CodeT5 (~67 min on Apple Silicon)
PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_binary.py \
  --model codet5 --epochs 5 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 2 --max-length 256 --max-samples 20000

# Train GraphCodeBERT (~59 min on Apple Silicon)
PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_binary.py \
  --model graphcodebert --epochs 5 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 2 --max-length 256 --max-samples 20000

# Compare and select winner
python src/evaluation/evaluate_binary.py --compare

# Test inference
python src/evaluation/evaluate_binary.py --predict --model codet5 \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

### 4. Phase 2 — Train CWE classifier

```bash
# Train CWE classifier (~80 min on Apple Silicon)
PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_cwe.py \
  --epochs 10 --batch-size 8 --grad-accum 4 \
  --lr 2e-4 --patience 3 --max-length 256

# View results
python src/evaluation/evaluate_cwe.py --evaluate

# Test CWE inference
python src/evaluation/evaluate_cwe.py --predict \
  --code "int main() { char buf[10]; gets(buf); return 0; }"
```

---

## 14. Known Issues & Fixes Applied

| Issue | Cause | Fix Applied |
|-------|-------|-------------|
| **TensorFlow mutex deadlock** | TF 2.20 on macOS causes `[mutex.cc : 452] RAW: Lock blocking` when loading transformers models | Set `os.environ["USE_TF"] = "0"` at the top of every training/eval script before importing transformers |
| **SSL download hang** | Python 3.9 + macOS LibreSSL can't connect to HuggingFace Hub | Downloaded model weights manually via `curl` to `models/pretrained/`, scripts use `resolve_model_path()` to auto-detect local files |
| **MPS out-of-memory** | Apple Silicon MPS GPU runs out of memory with large batch sizes | Set `PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0` and use `batch-size 8` + `max-length 256` |
| **bitsandbytes warning** | bitsandbytes compiled without GPU support on macOS | Harmless warning — 4-bit quantization is only needed for Phase 4 (LLMs), not for encoder fine-tuning |

---

## 15. What's Left to Do

| Phase | Description | What will be done |
|-------|-------------|-------------------|
| **3** | Severity Scoring | Predict continuous CVSS scores (0–10) as a regression task using CodeT5 + regression head. Evaluate with MAE, MSE, R². Derive Low/Medium/High/Critical categories from predicted scores. |
| **4** | LLM Code Refinement | Use Mistral-7B-Instruct and DeepSeek-Coder to generate fixed versions of vulnerable code via prompting. No fine-tuning — just prompt engineering. 4-bit quantization to fit in GPU memory. |
| **5** | Streamlit App | Build a web UI where users paste code and get: vulnerability detection → CWE type → severity score → suggested fix, all in one pipeline. |
| **6** | Final Report | Write complete evaluation, ablation studies, comparison with baselines, and project report. |

---

## Technology Stack Summary

```
┌─────────────────────────────────────────────────────────┐
│                      SecuraX Pipeline                    │
├──────────┬──────────┬──────────┬────────────────────────┤
│ Phase 1  │ Phase 2  │ Phase 3  │ Phase 4               │
│ Detect   │ Classify │ Score    │ Fix                    │
│          │          │          │                        │
│ CodeT5   │ CodeT5   │ CodeT5   │ Mistral-7B-Instruct   │
│ +LoRA    │ +LoRA    │ +LoRA    │ DeepSeek-Coder-6.7B   │
│ Binary   │ 24-class │ Regress  │ Prompting              │
│ head     │ head     │ head     │ (4-bit quantized)      │
├──────────┴──────────┴──────────┴────────────────────────┤
│ Dataset: BigVul (217K C/C++ functions)                  │
│ Framework: PyTorch + HuggingFace Transformers + PEFT    │
│ Hardware: Apple Silicon MPS / NVIDIA CUDA / CPU         │
│ Everything: 100% free & open-source                     │
└─────────────────────────────────────────────────────────┘
```
