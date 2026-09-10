# SecuraX: An AI-Based Framework for Automated Source Code Vulnerability Detection, Multi-Class Classification, Severity Scoring and LLM-Assisted Code Refinement

## Problem Statement

Given a source code file or snippet, this system **detects** whether the code is vulnerable, **classifies** the vulnerability type (CWE-id), assigns a **severity score** (CVSS 0–10), and produces a **refined/fixed version** of the code using LLM-based generation.

**Output format:** A table with columns:

| PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score |
|----|---------|-----|--------|--------------|-----|----------------|
| C  | `...`   | 1   | CWE-119 | `...`       | 12  | 7.5            |

**Primary metric:** Recall (with Precision, F1, and AUROC tracked alongside).

---

## Team Roles

| Person | Role | Responsibility |
|--------|------|----------------|
| **A** | Detection / Classification / Severity | Supervised fine-tuning of CodeT5 & GraphCodeBERT for vulnerability detection, CWE classification, and severity scoring |
| **B** | LLM-Based Code Refinement | Prompting-based code fixing using Mistral-7B-Instruct & DeepSeek-Coder-Instruct (no ground-truth fixed code in dataset) |

---

## Tool Stack

> **Hard constraint:** Every tool, library, model, and dataset is **free and open-source** (MIT/Apache-2.0/BSD/GPL or free-to-use research license). No paid APIs, no paid cloud, no subscriptions.

| Category | Tool | License | Purpose |
|----------|------|---------|---------|
| **Detection Encoders** | [CodeT5-base](https://huggingface.co/Salesforce/codet5-base) | Apache-2.0 | Vulnerability detection & CWE classification |
| | [GraphCodeBERT-base](https://huggingface.co/microsoft/graphcodebert-base) | MIT | Code understanding encoder |
| **Refinement LLMs** | [Mistral-7B-Instruct](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3) | Apache-2.0 | Code refinement/fixing (4-bit quantized) |
| | [DeepSeek-Coder-6.7B-Instruct](https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct) | Deepseek License | Code refinement/fixing (4-bit quantized) |
| **ML Framework** | PyTorch | BSD-3 | Deep learning framework |
| | HuggingFace Transformers | Apache-2.0 | Model loading & fine-tuning |
| | PEFT / LoRA | Apache-2.0 | Parameter-efficient fine-tuning |
| | bitsandbytes | MIT | 4-bit quantization |
| | Accelerate | Apache-2.0 | Device mapping & mixed precision |
| **Data Science** | scikit-learn, pandas, numpy | BSD-3 | Metrics, data processing |
| **Dataset** | [BigVul (MSR 2020)](https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset) | Research | ~188K C/C++ functions with CWE-ids & CVSS scores |
| **Static Analysis** | Bandit | Apache-2.0 | Python vulnerability scanner |
| | Cppcheck (system) | GPL-3.0 | C/C++ static analysis |
| **Web App** | Streamlit | Apache-2.0 | Interactive demo UI |
| **Optional** | vLLM | Apache-2.0 | Faster local LLM serving |

---

## Repository Structure

```
Minor Project/
├── data/
│   ├── raw/                    # Original datasets (gitignored)
│   └── processed/              # Preprocessed splits (gitignored)
├── notebooks/                  # Jupyter notebooks for exploration
├── src/
│   ├── __init__.py
│   ├── data/
│   │   ├── __init__.py
│   │   ├── dataset.py          # BigVulBinaryDataset, create_splits(), create_dataloaders()
│   │   ├── download_bigvul.py  # Dataset downloader
│   │   └── load_and_explore.py # Data exploration script
│   ├── models/
│   │   ├── __init__.py
│   │   ├── train_binary.py     # Phase 1 training (CodeT5/GraphCodeBERT + LoRA)
│   │   └── verify_models.py    # Model loading verification
│   ├── evaluation/
│   │   ├── __init__.py
│   │   └── evaluate_binary.py  # Phase 1 eval, comparison, and inference
│   └── utils/
│       └── __init__.py
├── models/
│   ├── pretrained/             # Locally cached base model weights
│   ├── checkpoints/            # Training checkpoints (gitignored)
│   └── saved/                  # Final saved models (gitignored)
│       └── phase1_winner/      # Best Phase 1 model (CodeT5 + LoRA)
├── docs/
│   ├── PHASE_0.md              # Phase 0 documentation
│   └── PHASE_1.md              # Phase 1 documentation
├── app/                        # Streamlit app (future phases)
├── logs/                       # Training logs & result JSONs
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Environment Setup

### Prerequisites

- **Python 3.10+** (tested with 3.13)
- **Git**
- **cppcheck** (system-level): `brew install cppcheck` (macOS) or `sudo apt install cppcheck` (Ubuntu)
- **GPU** (recommended): NVIDIA GPU with CUDA for 4-bit quantization, or Apple Silicon with MPS

### Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd "Minor Project"

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download the dataset
python src/data/download_bigvul.py

# 5. Explore the dataset
python src/data/load_and_explore.py

# 6. Verify models can be loaded
python src/models/verify_models.py          # Full verification
python src/models/verify_models.py --skip-large  # Encoders only
```

### Optional: Install cppcheck

```bash
# macOS
brew install cppcheck

# Ubuntu/Debian
sudo apt-get install cppcheck

# Verify
cppcheck --version
```

---

## Train/Val/Test Split Strategy

- **Method:** Stratified split by CWE-id
- **Ratios:** 70% Train / 15% Validation / 15% Test
- **Random seed:** 42 (for reproducibility)
- **Minimum samples per class:** 2 (classes with fewer samples are dropped)

---

## Project Status

**✅ Phase 1 complete** — Binary vulnerability detection baseline trained, evaluated, and winner selected (CodeT5).

| Phase | Description | Status |
|-------|-------------|--------|
| **0** | Scoping & Setup | ✅ Complete |
| **1** | Detection Baseline (Binary Classification) | ✅ Complete |
| 2 | CWE Multi-Class Classification | 🔲 Not started |
| 3 | Severity Scoring | 🔲 Not started |
| 4 | LLM-Based Code Refinement | 🔲 Not started |
| 5 | Integration & Streamlit App | 🔲 Not started |
| 6 | Evaluation & Final Report | 🔲 Not started |

---

## Detection Baseline Results (Phase 1)

**🏆 Winner: CodeT5** (with LoRA, rank=16, alpha=32)

| Metric | CodeT5 | GraphCodeBERT | Winner |
|--------|--------|---------------|--------|
| **Recall ★** | **0.5667** | 0.5533 | CodeT5 |
| Precision | **0.8586** | 0.8469 | CodeT5 |
| F1 | **0.6827** | 0.6694 | CodeT5 |
| AUROC | **0.9087** | 0.9062 | CodeT5 |
| Accuracy | **0.9737** | 0.9727 | CodeT5 |
| Loss ↓ | **0.1068** | 0.1174 | CodeT5 |

**Selection:** CodeT5 won on all 6 metrics. Recall is the primary metric (0.5667 vs 0.5533).

**Training config:** 20K samples (stratified), 5 epochs, batch=8, grad_accum=4, lr=2e-4, max_length=256, LoRA (r=16, α=32).

See [`docs/PHASE_1.md`](docs/PHASE_1.md) for full details, commands, and known limitations.
