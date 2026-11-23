# SecuraX: An AI-Based Framework for Automated Source Code Vulnerability Detection, Multi-Class Classification, Severity Scoring and LLM-Assisted Code Refinement

**Author:** Preet Makadiya  
**Academic Role:** B.Tech Minor Project  
**Guide / Advisor:** [GUIDE_NAME], [INSTITUTE_NAME]  
**Project Classification:** Research Prototype (Academic Evaluation)

## Project Status: ✅ Audit & Validation Complete — Neuro-Symbolic Pipeline Verified

SecuraX is an academic research prototype featuring an integrated, language-routed vulnerability intelligence and repair pipeline. Phases 1–3 run locally on PyTorch/PEFT neural models (GraphCodeBERT & CodeT5), combined with a calibrated static security override layer (`Controls detected - likely safe`) and hosted open-weight Groq LPU inference for Phase 4 code refinement. Phase 7 stretch goals integrate automated closed-loop self-verification and line-level attention explainability.

**Core Project Deliverables:**
- 📄 **Academic Final Report:** [`reports/FINAL_PROJECT_REPORT.md`](reports/FINAL_PROJECT_REPORT.md)
- 📊 **Presentation Slides (Technical Defense):** [`reports/PRESENTATION_SLIDES.md`](reports/PRESENTATION_SLIDES.md)
- 🎬 **Live Demo Script (with Plan B):** [`reports/LIVE_DEMO_SCRIPT.md`](reports/LIVE_DEMO_SCRIPT.md)
- 📈 **Consolidated Metrics Summary:** [`results/phase6_evaluation_summary.json`](results/phase6_evaluation_summary.json)
- 🔬 **Phase 7 Stretch Goals Summary:** [`results/phase7_evaluation_summary.json`](results/phase7_evaluation_summary.json)
- 📖 **Phase 7 Documentation:** [`docs/PHASE_7.md`](docs/PHASE_7.md)
- 🖥️ **Interactive Web App Launch:** `streamlit run app/main.py`

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
| **Datasets** | [BigVul (MSR 2020)](https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset) | Research | ~188K C/C++ functions with CWE-ids & CVSS scores |
| | [CVEFixes](https://github.com/secureIT-project/CVEfixes) | Research | Multi-language (C/C++/Python/Java/JS/Go/PHP/C#/Ruby), real fix pairs |
| | [MegaVul](https://github.com/Icyrockton/MegaVul) | Research | Additional C/C++ & Java volume |
| | [DiverseVul](https://github.com/wagner-group/diversevul) | Research | Cleaner C/C++ labels |
| | [VUDENC](https://github.com/LauraWartschinski/VulnerabilityDetection) | Research | Python-specific vulnerabilities |
| **Language Detection** | Pygments | BSD-2 | Language detection via `guess_lexer()` |
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
│       ├── manifest.json       # Counts, tier assignments, split info
│       ├── tier1_c_cpp/        # Tier 1 splits (vf/cwe/severity/repair)
│       ├── tier2_<lang>/       # Tier 2 per-language splits
│       └── tier3_shared/       # Tier 3 shared model splits
├── notebooks/                  # Jupyter notebooks for exploration
├── src/
│   ├── __init__.py
│   ├── data/
│   │   ├── __init__.py
│   │   ├── dataset.py          # BigVulBinaryDataset, create_splits(), create_dataloaders()
│   │   ├── dataset_cwe.py      # BigVulCWEDataset, CWE label mapping, CWE dataloaders
│   │   ├── download_bigvul.py  # BigVul dataset downloader
│   │   ├── download_datasets.py # Phase 0.5: All 5 datasets downloader
│   │   ├── audit_multilang.py  # Phase 0.5: Multi-language audit & tiering
│   │   ├── dataset_multilang.py # Multi-tier data pipeline (Phase 1 revised)
│   │   ├── dataset_severity.py # Phase 3: Severity score dataset & loaders
│   │   ├── dataset_repair.py  # Phase 4: Code repair fix-pair dataset & loaders
│   │   └── load_and_explore.py # Data exploration script
│   ├── models/
│   │   ├── __init__.py
│   │   ├── modules.py          # Shared: AttentionPooling, FocalLoss, class weights
│   │   ├── train_binary.py     # Phase 1 v1 training (C/C++ only, old recipe)
│   │   ├── train_binary_v2.py  # Phase 1 v2 training (multi-tier, revised recipe)
│   │   ├── run_phase1_all_tiers.py # Orchestrator: trains ALL tier/model combos
│   │   ├── train_cwe.py        # Phase 2 training (15-class CWE classification)
│   │   ├── train_codebert_moo.py # Phase 2 AIBugHunter MOO (multi-objective)
│   │   ├── run_phase2_all_tiers.py # Phase 2 orchestrator
│   │   ├── train_severity.py   # Phase 3 severity scoring (CVSS regression)
│   │   ├── run_phase3_all_tiers.py # Phase 3 orchestrator
│   │   ├── train_repair.py    # Phase 4 code repair (CodeT5 fine-tuning + zero-shot)
│   │   ├── run_phase4_all.py  # Phase 4 orchestrator
│   │   ├── min_norm_solvers.py # MGDA / Frank-Wolfe Pareto solver
│   │   └── verify_models.py    # Model loading verification
│   ├── evaluation/
│   │   ├── __init__.py
│   │   ├── evaluate_binary.py  # Phase 1 v1 eval (C/C++ only)
│   │   ├── evaluate_binary_v2.py # Phase 1 v2 eval (multi-tier, threshold sweep)
│   │   ├── evaluate_cwe.py     # Phase 2 v1 eval, confusion matrix
│   │   ├── evaluate_cwe_v2.py  # Phase 2 v2 eval (multi-tier, 15-class)
│   │   ├── evaluate_severity.py # Phase 3 eval (MAE, RMSE, per-band)
│   │   └── evaluate_repair.py # Phase 4 eval (PP, BLEU, syntax, VF flip)
│   └── utils/
│       └── __init__.py
├── models/
│   ├── pretrained/             # Locally cached base model weights
│   ├── checkpoints/            # Training checkpoints (gitignored)
│   └── saved/                  # Final saved models (gitignored)
│       ├── phase1_winner_<tier>/ # Phase 1 per-tier winners (binary VF detection)
│       ├── phase2_winner_<tier>/ # Phase 2 per-tier winners (15-class CWE)
│       ├── phase3_A_<tier>_<model>/ # Phase 3 severity models (Approach A)
│       └── phase4_<method>_<tier>_codet5/ # Phase 4 repair models
├── results/                    # Consolidated model results & summaries
│   ├── phase0_5_audit_results.md
│   ├── phase1_binary_detection_results.md
│   ├── phase2_cwe_classification_results.md
│   └── phase3_severity_scoring_results.md
│   └── phase4_code_repair_results.md
├── docs/
│   ├── PHASE_0.md              # Phase 0 documentation
│   ├── PHASE_0.5.md            # Phase 0.5 multi-language data audit
│   ├── PHASE_1.md              # Phase 1 multi-tier binary detection
│   ├── PHASE_2.md              # Phase 2 v2 multi-tier CWE classification
│   ├── PHASE_2_v1_superseded.md # Phase 2 v1 archival (24-class baseline)
│   ├── PHASE_3.md              # Phase 3 multi-tier severity scoring
│   └── PHASE_4.md              # Phase 4 LLM-based code repair
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

**✅ All Phases (0 through 7) Complete. Full End-to-End Pipeline & Stretch Goals Operational.**

| Phase | Description | Status | Reference Doc |
|---|---|:---:|---|
| **0** | Scoping, Environment Setup & Pretrained Verification | ✅ Complete | [`docs/PHASE_0.md`](docs/PHASE_0.md) |
| **0.5** | Multi-Language Data Audit & 3-Tier Allocation (540K functions) | ✅ Complete | [`docs/PHASE_0.5.md`](docs/PHASE_0.5.md) |
| **1** | Multi-Tier Binary Vulnerability Detection Baseline | ✅ Complete | [`docs/PHASE_1.md`](docs/PHASE_1.md) |
| **2** | Multi-Tier CWE Multi-Class Classification (15 Semantic Groups) | ✅ Complete | [`docs/PHASE_2.md`](docs/PHASE_2.md) |
| **3** | Severity Scoring (CVSS 0–10 Regression, Approach A) | ✅ Complete | [`docs/PHASE_3.md`](docs/PHASE_3.md) |
| **4** | LLM-Based Code Refinement (Groq-Hosted Open-Weight Models) | ✅ Complete | [`docs/PHASE_4.md`](docs/PHASE_4.md) |
| **5** | Integration & Interactive Streamlit Web Application | ✅ Complete | [`docs/PHASE_5.md`](docs/PHASE_5.md) |
| **6** | Consolidated Benchmarks, Ablations & Academic Deliverables | ✅ Complete | [`docs/PHASE_6.md`](docs/PHASE_6.md) |
| **7** | Stretch Goals: Option B (Self-Verification Loop) & Option C (Attention Explainability) | ✅ Complete | [`docs/PHASE_7.md`](docs/PHASE_7.md) |

---

## Multi-Language Data Coverage (Phase 0.5)

**Approach:** Multi-model, tiered by data volume — one model per tier, not one universal model.

| Tier | Threshold | Expected Languages | Models |
|------|-----------|--------------------|--------|
| **Tier 1** | ≥ 50K samples | C/C++ | CodeT5 + GraphCodeBERT + VulBERTa |
| **Tier 2** | 2K – 50K | Python, JavaScript, PHP | CodeT5 + GraphCodeBERT (warm-started from Tier 1) |
| **Tier 3** | < 2K | Java, Go, C#, Ruby | Shared CodeT5 + GraphCodeBERT (with `<LANG=xx>` token) |

**Datasets:** BigVul, CVEFixes, MegaVul, DiverseVul, VUDENC — combined and deduplicated across datasets.

**Language detection:** Pygments `guess_lexer()` (BSD-2) + file extension fallback.

> **Note:** Actual tier assignments are determined by running `python src/data/audit_multilang.py` and may differ from the expected values above. See [`docs/PHASE_0_5.md`](docs/PHASE_0_5.md) for full methodology.

---

## Detection Baseline Results (Phase 1 — Multi-Tier)

**Multi-tier binary vulnerability detection** trained on **540K deduplicated samples** across 11 languages using LoRA ($r=64, \alpha=128$), Focal Loss, and decision threshold sweeps.

| Tier | Language(s) | 🏆 Winner | Optimal Thr | Test Recall | Test F1 | Test Accuracy |
|---|---|---|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **GraphCodeBERT** | 0.70 | 0.4580 | **0.5703** | 0.9262 |
| **Tier 2** | C++ | **GraphCodeBERT** | 0.10 | 0.9949 | **0.9843** | 0.9776 |
| **Tier 2** | PHP | **CodeT5** | 0.10 | 1.0000 | **1.0000** | 1.0000 |
| **Tier 2** | Python | **GraphCodeBERT** | 0.15 | 0.8545 | **0.8174** | 0.9729 |
| **Tier 3** | Shared (Go, Java, JS, Ruby, TS) | **CodeT5** | 0.50 | 0.8412 | **0.8330** | 0.9410 |

See [`docs/PHASE_1.md`](docs/PHASE_1.md) for full details, per-tier threshold sweeps, and reproduction commands.

---

## CWE Classification Results (Phase 2 — Multi-Tier, v2 Semantic Grouping)

**15 MITRE CWE-1000 semantic groups** replacing the earlier v1 24-class taxonomy. Uses LoRA ($r=64, \alpha=128$), Focal Loss ($\gamma=2.0$), WeightedRandomSampler, and a debugged calibrated ensemble ($w=0.65, T=1.5$). Includes AIBugHunter CodeBERT-MOO multi-objective model.

| Tier | Language(s) | 🏆 Winner | Macro-Recall | Macro-F1 | Accuracy |
|---|---|---|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **Calibrated Ensemble** | **0.6513** | **0.6894** | 0.6895 |
| **Tier 2** | C++ | **GraphCodeBERT-v2** | 0.7950 | **0.8124** | 0.8251 |
| **Tier 2** | Python | **GraphCodeBERT-v2** | 0.7480 | **0.7640** | 0.7917 |
| **Tier 2** | PHP | **CodeT5-v2** | 0.9320 | **0.9412** | 0.9540 |
| **Tier 3** | Shared (Go, Java, JS, etc.) | **CodeT5-v2** | 0.7710 | **0.7850** | 0.8102 |

**Tier 1 improvement over Phase 2 v1:** Macro-Recall **+49.8%**, Macro-F1 **+114.6%**.

See [`docs/PHASE_2.md`](docs/PHASE_2.md) for full per-class metrics, confusion matrices, and ensemble calibration details.

---

## Severity Scoring Results (Phase 3 — Approach A, Per-Tier)

**CVSS 0–10 continuous regression** predicting vulnerability severity for prioritization. Only Approach A (single-task per-tier) was completed; Approaches B (multi-task) and C (shared) were deferred to prioritize Phase 4.

| Tier | Language(s) | 🏆 Model | Test MAE ↓ | Test RMSE | R² | Band Acc |
|---|---|---|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **CodeT5** | **1.357** | 1.777 | -0.154 | 67.66% |
| **Tier 2** | C++ | GraphCodeBERT | 1.499 | 2.038 | -0.187 | 68.42% |
| **Tier 2** | Python | GraphCodeBERT | **1.269** | 1.643 | -0.016 | **73.53%** |
| **Tier 2** | PHP | **CodeT5** | **1.167** | 1.454 | -0.009 | 68.26% |
| **Tier 3** | Shared (7 langs) | CodeT5 | — (val=1.200) | — | — | — |

> **Key finding:** All models show negative R² (worse than mean-baseline prediction), indicating CVSS severity is poorly predicted from code tokens alone. Models achieve reasonable Medium-band accuracy (MAE ≈ 0.7–0.8) but fail on Critical scores (MAE ≈ 4.5–5.2), exhibiting strong mean-regression bias toward ~5.0.

See [`docs/PHASE_3.md`](docs/PHASE_3.md) and [`results/phase3_severity_scoring_results.md`](results/phase3_severity_scoring_results.md) for full per-band breakdown, training details, and known limitations.

---

## Code Refinement (Phase 4 — Groq-Hosted LLM API)

**Automated vulnerability repair** using high-speed hosted inference with open-weight instruction models on Groq's LPU hardware. Evaluated across 100 multi-language test fix-pairs from BigVul and CVEFixes.

> ### ⚠️ Constraint Exception
> Groq is a hosted API serving open-weight models on a free tier. The service is hosted, rate-limited, and transmits code to Groq infrastructure for inference. Free-tier terms and model availability can change. All other project components remain 100% free/open-source.

### Model Comparison & Results Summary

| Evaluation Metric | Description | 🏆 `qwen/qwen3.8-27b` (Default) | `openai/gpt-oss-120b` (Alternate) |
|---|---|:---:|:---:|
| **Perfect Prediction (PP)** | Whitespace-normalized exact match vs real fix | **28.0%** | 18.0% |
| **Exact Match (EM)** | Strict string equality against real fix | **14.0%** | 8.0% |
| **Normalized Edit Similarity** | Levenshtein sequence ratio vs real fix | **0.782** | 0.694 |
| **Token BLEU-4** | Token overlap with ground truth patch | **58.4** | 49.1 |
| **Syntactic Validity** | Compiler & syntax parser validation | **96.0%** | 92.0% |
| **Detector Flip Rate (VF Flip)** | Phase 1 model re-evaluation (Vuln → Safe) | **79.0%** | 68.0% |
| **Average Latency** | Time per refinement generation call | **1.14s** | 2.48s |

### Qualitative Manual Review (40 Samples)
- **Fixed (Clean Security Patch):** 31 / 40 (77.5%)
- **Partial Fix (Security logic improved):** 8 / 40 (20.0%)
- **Broke Behavior:** 1 / 40 (2.5%)
- **Unchanged:** 0 / 40 (0.0%)

### Setting Up & Running
```bash
# 1. Add free key to .env (see .env.example)
echo "GROQ_API_KEY=your_key_here" >> .env

# 2. Run full 100-sample benchmark comparison
python src/models/run_phase4_all.py --samples 100 --manual-samples 40
```

See [`docs/PHASE_4.md`](docs/PHASE_4.md) for full architecture, prompt template, rate limiting, and known limitations.

---

## Pipeline Integration & Interactive Dashboard (Phase 5)

An end-to-end multi-tier pipeline and interactive Streamlit web dashboard connecting language detection, AST function chunking, binary detection, CWE classification, CVSS severity regression, and LLM code repair.

### Launching the Dashboard

```bash
# 1. Activate your virtual environment
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 2. Configure API key(s) in .env (or via st.secrets)
# GROQ_API_KEY=gsk_your_key_here
# GROQ_API_KEY_FALLBACK=gsk_optional_backup_key_here

# 3. Launch Streamlit
streamlit run app/main.py
```

### Dashboard Features

1. **Language Routing & AST Function Chunker:**
   - Detects language using Pygments `guess_lexer()` and file extension override.
   - Parses incoming source code into discrete functions using Python `ast` and language-specific brace matching.
2. **Supported Languages (Dynamically read from `data/processed/manifest.json`):**
   - **Tier 1:** `C` (`.c`, `.h`)
   - **Tier 2:** `C++` (`.cpp`, `.hpp`), `Python` (`.py`), `PHP` (`.php`)
   - **Tier 3 (Shared):** `Go` (`.go`), `Java` (`.java`), `JavaScript` (`.js`), `TypeScript` (`.ts`), `Ruby` (`.rb`), `JSON` (`.json`)
   - *Unsupported languages (Rust, Swift, Shell, etc.) are rejected with an explicit notice and never routed to an arbitrary tier.*
3. **Exact Results Schema Table:**
   - Standard output table conforming strictly to:  
     `PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score`
   - Highlights vulnerable functions in red and safe functions in green.
4. **Interactive Unified Diffs:**
   - Expands vulnerable functions into color-coded side-by-side diff views showing exact patched lines.
5. **Quota Protection & On-Demand Repair:**
   - Enforces a configurable refinement cap (default: 20 calls) to conserve free-tier API quotas.
   - For functions exceeding the cap, provides an interactive **"Refine on Demand"** button.
6. **Graceful Degradation:**
   - If `GROQ_API_KEY` is missing or invalid, detection, CWE classification, and severity scoring continue normally on local PyTorch models, with refinement cells clearly indicating `"Refinement unavailable: GROQ_API_KEY is not set"`.

See [`docs/PHASE_5.md`](docs/PHASE_5.md) for complete pipeline specifications, test suite details, and edge case coverage.

---

## Evaluation, Ablations & Project Writeup (Phase 6)

A comprehensive cross-tier evaluation matrix consolidating detection, CWE classification, continuous severity regression, and automated code repair across all language tiers.

### Consolidated Performance Matrix

| Tier | Language(s) | 🏆 Winner Model | Phase 1 VF F1 | Phase 1 Recall | Phase 2 CWE Macro-F1 | Phase 3 CVSS MAE | Refinement Edit Sim | Refinement BLEU-4 |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | GraphCodeBERT + Ens | **0.5703** | 0.4580 | **0.6894** | **1.357** | **0.729** | **52.4** |
| **Tier 2** | C++ | GraphCodeBERT-v2 | **0.9843** | 0.9949 | **0.8124** | 1.499 | **0.764** | **58.1** |
| **Tier 2** | Python | GraphCodeBERT-v2 | **0.8174** | 0.8545 | **0.7640** | **1.269** | **0.814** | **61.2** |
| **Tier 2** | PHP | CodeT5-v2 | **1.0000** | 1.0000 | **0.9412** | **1.167** | **0.835** | **64.0** |
| **Tier 3** | Shared | CodeT5-v2 + `<LANG>` | **0.8330** | 0.8412 | **0.7850** | 1.200* | **0.792** | **59.5** |

### Key Ablation Discoveries

1. **Ablation 1 (Zero-Shot LLM vs Fine-Tuning):** Evaluated `qwen/qwen3.8-27b` zero-shot for vulnerability detection. Achieved high Recall (1.00) but poor Precision (0.556) with a 44% false alarm rate on safe code, proving fine-tuned code models are mandatory.
2. **Ablation 2 (Taxonomy Reform):** 15 MITRE semantic groups boosted Macro-Recall by **+49.8%** and Macro-F1 by **+114.6%** over v1.
3. **Ablation 3 (Synthetic vs In-The-Wild):** Synthetic Juliet/SARD yields artificially inflated F1 (0.942) that drops to 0.570 on real CVEs (-0.372 gap).
4. **Ablation 4 (Severity Modeling):** Continuous CVSS severity prediction from code tokens alone is bounded by mean regression toward ~5.38.
5. **Ablation 5 (Refinement Context):** Supplying upstream CWE and severity context guides LLMs to produce domain-precise security constructs without signature drift.

See [`docs/PHASE_6.md`](docs/PHASE_6.md) for full reproduction commands, sample IDs, and language-specific error analysis.

---

## Phase 7: Stretch Goals (Self-Verification Loop & Line Explainability)

SecuraX implements two cutting-edge stretch capabilities extending beyond traditional static or one-shot LLM repair pipelines:

### 1. Option B — Self-Verification Loop (Automated Closed-Loop Repair)
- Evaluates candidate patches ($P_1$) using the Phase 1 Binary Detector, AST syntax parsers, and static analysis tools (`bandit` for Python, `cppcheck` for C/C++).
- If residual vulnerability is flagged, automatically formulates a structured diagnostic prompt containing detector confidence, model attention lines, and static warnings, and re-prompts the Groq LLM for Pass 2 ($P_2$).
- Benchmarked across multi-language pairs (`results/phase7_evaluation_summary.json`): successfully caught residual vulnerabilities with modest extra token overhead (average 328.8 tokens).

### 2. Option C — Line-Level Explainability (Attention Pooling Heatmap)
- Extracts scalar attention weights $\alpha \in \mathbb{R}^L$ directly from the `AttentionPooling` classification head in `GraphCodeBERTV2`.
- Projects token-level subword attention onto source line offsets, computing normalized line suspicion scores.
- **Top-1 Attribution Accuracy:** **50.0%**; **Top-3 Attribution Accuracy:** **100.0%** (ground-truth vulnerable statement always captured in top-3 flagged lines).
- Displays color-coded CSS gradient heatmaps and line attribution cards in the Streamlit UI with sub-second inference latency (~1.1s on CPU).

See [`docs/PHASE_7.md`](docs/PHASE_7.md) for full architecture diagrams, prompt templates, and benchmark metrics.



