# 🛡️ VulnDetect — Automated Code Vulnerability Detection, Classification & Severity Scoring

## Problem Statement

Software vulnerabilities in open-source code continue to be a leading cause of security breaches. This project builds an end-to-end ML pipeline that, given a source code snippet, **(1)** detects whether it is vulnerable, **(2)** classifies the vulnerability type (CWE-id), **(3)** assigns a severity score (CVSS-based), and **(4)** generates a refined/fixed version of the code using an LLM. The final output is a structured table with columns: **PL, Snippet, VF, CWE-id, Refined Code, LOC, Severity Score**. The primary evaluation metric is **Recall**, with Precision, F1, and AUROC tracked alongside.

## Team Roles

| Person | Role | Approach |
|--------|------|----------|
| **Person A** | Detection, Classification, Severity Scoring | Supervised fine-tuning (CodeBERT / UnixCoder + LoRA) |
| **Person B** | LLM-based Code Refinement | Prompting-based (Mistral-7B / DeepSeek-Coder via Ollama) — no ground-truth fixes in dataset |

## Tech Stack (100% Free & Open-Source)

| Category | Tool/Library | License | Notes |
|----------|-------------|---------|-------|
| **Detection Encoder** | [CodeBERT](https://huggingface.co/microsoft/codebert-base) | MIT | Pre-trained code understanding model |
| **Detection Encoder** | [UnixCoder](https://huggingface.co/microsoft/unixcoder-base) | MIT | Alternative encoder |
| **Refinement LLM** | [Mistral-7B-Instruct](https://ollama.com/library/mistral) | Apache-2.0 | Via Ollama (local) |
| **Refinement LLM** | [DeepSeek-Coder-Instruct](https://ollama.com/library/deepseek-coder) | DeepSeek License | Via Ollama (local) |
| **Fine-Tuning** | [PEFT/LoRA](https://github.com/huggingface/peft) | Apache-2.0 | Parameter-efficient fine-tuning |
| **ML Framework** | [PyTorch](https://pytorch.org/) | Apache-2.0 | Deep learning backend |
| **Transformers** | [HuggingFace Transformers](https://huggingface.co/transformers) | Apache-2.0 | Model loading & tokenization |
| **Static Analysis** | [Bandit](https://bandit.readthedocs.io/) | Apache-2.0 | Python security linter |
| **Static Analysis** | [Cppcheck](http://cppcheck.net/) | GPL-3.0 | C/C++ static analyzer (system install) |
| **Web App** | [Streamlit](https://streamlit.io/) | Apache-2.0 | Interactive demo UI |
| **Dataset** | [BigVul (MSR 2020)](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) | Research | Primary dataset |
| **Dataset** | CVEfixes | Research | Optional cross-check |
| **Evaluation** | [scikit-learn](https://scikit-learn.org/) | BSD-3 | Metrics & splitting |
| **LLM Runtime** | [Ollama](https://ollama.com/) | MIT | Local LLM server (system install) |

## Repository Structure

```
Minor Project/
├── README.md                  # ← This file (living summary)
├── requirements.txt           # Python dependencies (pip)
├── run_phase0_checks.py       # Master Phase 0 verification script
├── .gitignore
│
├── data/
│   ├── raw/                   # Original datasets (git-ignored)
│   └── processed/             # Cleaned/split data (git-ignored)
│
├── src/
│   ├── __init__.py
│   ├── config.py              # Central project configuration
│   ├── data/
│   │   ├── __init__.py
│   │   ├── download_bigvul.py # Dataset download helper
│   │   └── load_data.py       # Data loading & exploration
│   ├── models/
│   │   └── __init__.py        # (Phase 1+: detection/classification models)
│   ├── pipelines/
│   │   └── __init__.py        # (Phase 3+: end-to-end pipeline)
│   └── utils/
│       ├── __init__.py
│       ├── verify_hf_model.py # HuggingFace model verification
│       └── verify_ollama.py   # Ollama installation verification
│
├── models/
│   ├── checkpoints/           # Saved model weights (git-ignored)
│   └── configs/               # Training configurations
│
├── notebooks/                 # Jupyter notebooks for exploration
├── docs/                      # Phase documentation
│   └── PHASE_0.md
├── app/
│   └── main.py                # Streamlit web app (placeholder)
└── tests/                     # Unit tests (Phase 2+)
```

## Environment Setup

### Prerequisites

- **Python 3.10+** (tested with 3.13.1)
- **Git**
- **Ollama** (system-level install for LLM inference)
- **Cppcheck** (system-level install for C/C++ static analysis)

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd "Minor Project"

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install system-level tools
# macOS:
brew install ollama cppcheck
# Ubuntu/Debian:
# sudo apt install cppcheck
# curl -fsSL https://ollama.com/install.sh | sh

# 5. Start Ollama server (keep running in background)
ollama serve &

# 6. Download the dataset
python -m src.data.download_bigvul

# 7. Run all Phase 0 checks
python run_phase0_checks.py
```

### Quick Verification

```bash
# Explore the dataset
python -m src.data.load_data

# Test HuggingFace model loading
python -m src.utils.verify_hf_model

# Test Ollama
python -m src.utils.verify_ollama

# Launch the (placeholder) web app
streamlit run app/main.py
```

## Train/Val/Test Split Strategy

| Split | Ratio | Strategy |
|-------|-------|----------|
| Train | 80% | Stratified by vulnerability flag + CWE-id |
| Validation | 10% | Same stratification |
| Test | 10% | Same stratification |

- **Seed:** 42 (reproducible across runs)
- **Stratification:** Composite key — vulnerable samples are stratified by CWE-id; non-vulnerable samples form their own stratum. CWE classes with < 5 samples are grouped into a "rare" bucket to prevent split failures.

## Project Status

> **✅ Phase 0 — Scoping & Setup: COMPLETE**

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Scoping & Setup | ✅ Complete |
| 1 | Vulnerability Detection (Binary) | 🔲 Not started |
| 2 | CWE Classification (Multi-class) | 🔲 Not started |
| 3 | Severity Scoring | 🔲 Not started |
| 4 | LLM Code Refinement | 🔲 Not started |
| 5 | Streamlit App & Integration | 🔲 Not started |
