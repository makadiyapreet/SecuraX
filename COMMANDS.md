# SecuraX — All Commands (Phase-Wise)

> One file, every command, organized by phase.
> **Mac** and **Windows** sections separated. All commands are single-line (no line continuations).

---

## 📋 Quick Reference

| Task                                 | Machine                     | Why                                   |
| ------------------------------------ | --------------------------- | ------------------------------------- |
| Code editing, docs, git              | **Mac**                     | IDE convenience                       |
| Phase 0.5 data audit                 | **Either**                  | No GPU needed, ~30 min                |
| Phase 1–3 training                   | **Windows (CUDA)**          | bf16, batch=32, 20GB VRAM             |
| Phase 4 CodeT5 fine-tuning           | **Mac (MPS) ✅** or Windows | CodeT5 220M params + LoRA fits on MPS |
| Phase 4 zero-shot (Mistral/DeepSeek) | **Windows (CUDA) only**     | bitsandbytes 4-bit requires CUDA      |
| Smoke testing                        | **Mac (MPS)**               | Quick validation, 200–500 samples     |
| Streamlit app                        | **Either**                  | No GPU needed                         |

### Current Tier Assignments (from Phase 0.5)

| Tier       | Languages                           | Samples | Data Dir                       |
| ---------- | ----------------------------------- | ------- | ------------------------------ |
| **Tier 1** | C                                   | 516,562 | `data/processed/tier1_c_cpp/`  |
| **Tier 2** | C++                                 | 7,548   | `data/processed/tier2_cpp/`    |
| **Tier 2** | Python                              | 10,483  | `data/processed/tier2_python/` |
| **Tier 2** | PHP                                 | 2,100   | `data/processed/tier2_php/`    |
| **Tier 3** | Go, Java, JS, Ruby, TS, JSON, Other | 3,221   | `data/processed/tier3_shared/` |

---

# 🍎 macOS Commands

## Environment Setup (one-time)

```bash
cd SecuraX
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
brew install cppcheck
```

## Phase 0 — Scoping & Setup ✅

```bash
# Download BigVul dataset
python src/data/download_bigvul.py

# Explore dataset
python src/data/load_and_explore.py

# Verify all models can load
python src/models/verify_models.py --skip-large
```

## Phase 0.5 — Data Audit & Tiering ✅

```bash
# Run audit (downloads 5 datasets, deduplicates, creates splits)
python src/data/audit_multilang.py

# Verify manifest
python -c "import json; m=json.load(open('data/processed/manifest.json')); print(json.dumps(m['tier_assignments'], indent=2))"
```

## Phase 1 — Binary Detection (Mac smoke-test only)

```bash
# Smoke-test with small sample on MPS
PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0 python src/models/train_binary.py --model codet5 --epochs 5 --batch-size 8 --grad-accum 4 --lr 2e-4 --patience 2 --max-length 256 --max-samples 20000

# Compare models
python src/evaluation/evaluate_binary.py --compare

# Test inference
python src/evaluation/evaluate_binary.py --predict --model codet5 --code "int main() { char buf[10]; gets(buf); return 0; }"
```

## Phase 2 — CWE Multi-Class Classification (Mac smoke-test & evaluation)

```bash
# Dry run orchestrator
python src/models/run_phase2_all_tiers.py --dry-run

# Smoke-test CodeT5-v2 on MPS (small sample)
python src/models/train_cwe.py --model codet5 --tier tier1_c_cpp --epochs 1 --batch-size 4 --max-samples 200

# Smoke-test CodeBERT-MOO on MPS (small sample)
python src/models/train_codebert_moo.py --tier tier1_c_cpp --epochs 1 --batch-size 4 --max-samples 200

# Evaluate Fixed & Calibrated Ensemble
python src/models/train_cwe.py --ensemble --variant-tag v2

# Compare all Phase 2 variants across tiers
python src/evaluation/evaluate_cwe_v2.py --compare-all

# Export winner checkpoints
python src/evaluation/evaluate_cwe_v2.py --select-winners
```

## Phase 3 — Severity Scoring (Mac smoke-test only)

```bash
# Smoke-test Approach A (single-task per-tier) on MPS
python src/models/train_severity.py --approach A --model codet5 --tier tier1_c_cpp --epochs 2 --batch-size 4 --max-samples 100

# Smoke-test Approach C (shared cross-tier) on MPS
python src/models/train_severity.py --approach C --model codet5 --epochs 2 --batch-size 4 --max-samples 200

# Dry run orchestrator
python src/models/run_phase3_all_tiers.py --dry-run

# Compare all Phase 3 results
python src/models/train_severity.py --evaluate-all
python src/evaluation/evaluate_severity.py --compare-all
```

## Phase 4 — Code Refinement (Groq-Hosted LLM API ✅ — Any Machine)

> **Runs on macOS, Linux, or Windows.** No local GPU or 4-bit quantization required.
> Powered by Groq's high-speed inference engine using open-weight models (`qwen/qwen3.8-27b` and `openai/gpt-oss-120b`).
> **API Key Setup:** Set `GROQ_API_KEY` in `.env`.
> **Automatic Failover Pool:** If your primary key runs out of credits or hits a 429 rate limit, set `GROQ_API_KEY_FALLBACK` (or `GROQ_API_KEY_2`, `GROQ_API_KEYS=key1,key2`) in `.env`. The client automatically and instantly transfers requests to the fallback key without crashing!

### Step 1: Configure Keys & Verify Offline Fallback

```bash
cd SecuraX
source .venv/bin/activate    # macOS/Linux (.venv\Scripts\activate on Windows)

# 1. Edit .env with your key(s):
# GROQ_API_KEY=gsk_primary...
# GROQ_API_KEY_FALLBACK=gsk_backup...

# 2. Check Groq client initialization and key pool
python3 -c "from src.refinement.groq_client import GroqRefinementClient; c = GroqRefinementClient(); print(f'Client active: {c.is_available}, Keys in failover pool: {len(c.api_keys)}')"

# 3. Dry run orchestrator
python3 src/models/run_phase4_all.py --dry-run
```

### Step 2: Run Full Refinement Pipeline (Both Models)

```bash
# Full execution across 100 stratified test samples across 8+ languages
# Compares default (qwen/qwen3.8-27b) vs alternate (openai/gpt-oss-120b)
python3 src/models/run_phase4_all.py --samples 100 --manual-samples 40

# Or via train_repair.py wrapper:
python3 src/models/train_repair.py --backend groq --model both --samples 100
```

### Step 3: Run Single Model

```bash
# Run default model only
python3 src/refinement/run_refinement.py --model default --samples 100

# Run alternate model only
python3 src/refinement/run_refinement.py --model alternate --samples 100
```

### Step 4: Evaluate & Compare Results

```bash
# Compare all Phase 4 runs
python3 src/evaluation/evaluate_repair.py --compare-all

# Evaluate specific predictions file
python3 src/evaluation/evaluate_repair.py --predictions-file logs/phase4_predictions_qwen_qwen3.8_27b.json

# Generate manual review report
python3 src/evaluation/evaluate_repair.py --manual-review 40
```

### Check Phase 4 Outputs

```bash
# Telemetry logs
cat logs/groq_calls.jsonl | tail -20

# View comparison report
cat results/phase4_code_repair_results.md

# View qualitative manual review
cat results/phase4_manual_review.md
```

## Phase 5 — Pipeline Integration & Streamlit Dashboard (Mac / Any Machine)

```bash
# 1. Run full end-to-end multi-language test suite (5 files, 3 tiers, cap test, 429 failover test)
python3 tests/test_phase5_pipeline.py

# 2. Launch interactive Streamlit web dashboard
streamlit run app/main.py
```

## Phase 6 — Evaluation, Ablations & Report Artifacts (Mac / Any Machine)

```bash
# 1. Run all Phase 6 ablations and export consolidated metrics summary
python3 src/evaluation/run_phase6_evaluations.py

# 2. Inspect consolidated evaluation summary
cat results/phase6_evaluation_summary.json | python -m json.tool

# 3. View deliverables:
cat reports/FINAL_PROJECT_REPORT.md
cat reports/PRESENTATION_SLIDES.md
cat reports/LIVE_DEMO_SCRIPT.md
```

## Phase 7 — Stretch Goals: Self-Verification Loop & Line Explainability (Mac / Any Machine)

```bash
# 1. Benchmark Option B (Self-Verification Loop) & Option C (Attention Pooling Line Attribution)
python3 src/evaluation/run_phase7_evaluations.py

# 2. Inspect Phase 7 metrics & benchmark summary
cat results/phase7_evaluation_summary.json | python -m json.tool

# 3. View Phase 7 specification & documentation
cat docs/PHASE_7.md

# 4. Launch Streamlit UI with interactive Self-Verification badges & Attention Heatmaps
streamlit run app/main.py
```

## Utility Commands (Mac)

```bash
# Check MPS GPU
python -c "import torch; print(f'MPS available: {torch.backends.mps.is_available()}')"

# View manifest
cat data/processed/manifest.json | python -m json.tool

# List saved models
ls -lh models/saved/

# View training logs
cat logs/train_codet5_binary.log | tail -50

# Clear HuggingFace cache
rm -rf ~/.cache/huggingface/hub/
```

---

# 🪟 Windows Commands (PowerShell)

> **Important:** All commands are single-line. Do NOT use `\` for line continuation in PowerShell.

## Environment Setup (one-time)

```powershell
cd D:\Minor_Project-PD\SecuraX
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
pip install -r requirements.txt

# Verify CUDA
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}, GPU: {torch.cuda.get_device_name(0)}')"
```

### Troubleshooting

```powershell
# If torch doesn't see CUDA (prints "None"):
pip uninstall torch torchvision torchaudio
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# If bitsandbytes fails:
pip install bitsandbytes-windows

# Check GPU memory:
nvidia-smi
```

## Phase 0.5 — Data Audit & Tiering ✅ COMPLETED

```powershell
# Run audit (already done — 540,488 samples across 27 languages)
python src/data/audit_multilang.py

# Verify tier assignments
python -c "import json; m=json.load(open('data/processed/manifest.json')); print(json.dumps(m['tier_assignments'], indent=2))"
```

Result: `Tier 1: [C]` · `Tier 2: [C++, Python, PHP]` · `Tier 3: [Go, Java, JS, Ruby, TS, ...]`  
Full results: `results/phase0_5_audit_results.md`

---

## Phase 1 — Binary Vulnerability Detection

> Train tier-by-tier on Windows. Use `--max-samples` to control training time.
> Benchmark: ~44 min/epoch on RTX 4000 with bf16 and 50K samples (22 min train + 22 min val).

### Speed Reference (Tier 1 — C)

| Flags                            | Train Samples | Epochs |     Time      |
| -------------------------------- | :-----------: | :----: | :-----------: |
| (default, no --max-samples)      |     367K      |   10   | **very long** |
| `--max-samples 50000 --epochs 5` |      50K      |   5    | **~3.5 hrs**  |
| `--max-samples 50000 --epochs 3` |      50K      |   3    | **~2.2 hrs**  |

> **Tip:** `--max-samples` uses stratified subsampling — class balance is preserved.
> Val/test sets always stay full size (78K) for accurate evaluation.

### TIER 1: C (train one model at a time)

```powershell
# CodeT5 (~3.5 hours with 50K samples, 5 epochs — or ~2.2 hrs with 3 epochs)
python src/models/train_binary_v2.py --model codet5 --tier tier1_c_cpp --bf16 --max-samples 50000 --epochs 5

# GraphCodeBERT (~3.5 hours with 50K samples, 5 epochs)
python src/models/train_binary_v2.py --model graphcodebert --tier tier1_c_cpp --bf16 --max-samples 50000 --epochs 5

# VulBERTa zero-shot (no training, just evaluation, ~20 min)
python src/models/train_binary_v2.py --model vulberta --tier tier1_c_cpp --zero-shot

# VulBERTa fine-tuned (~2.2 hours with 50K samples, 3 epochs)
python src/models/train_binary_v2.py --model vulberta --tier tier1_c_cpp --bf16 --max-samples 50000 --epochs 3
```

### TIER 2: C++ (7.5K samples — small, no --max-samples needed)

```powershell
# CodeT5 warm-started from Tier 1 (~15 min)
python src/models/train_binary_v2.py --model codet5 --tier tier2_cpp --bf16 --warm-start models/saved/phase1_tier1_c_cpp_codet5/

# GraphCodeBERT (~15 min)
python src/models/train_binary_v2.py --model graphcodebert --tier tier2_cpp --bf16
```

### TIER 2: Python (10.5K samples — small, no --max-samples needed)

```powershell
# CodeT5 warm-started from Tier 1 (~20 min)
python src/models/train_binary_v2.py --model codet5 --tier tier2_python --bf16 --warm-start models/saved/phase1_tier1_c_cpp_codet5/

# GraphCodeBERT (~20 min)
python src/models/train_binary_v2.py --model graphcodebert --tier tier2_python --bf16
```

### TIER 2: PHP (2.1K samples — very small)

```powershell
# CodeT5 warm-started from Tier 1 (~5 min)
python src/models/train_binary_v2.py --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_tier1_c_cpp_codet5/
```

### TIER 3: Shared — Go, Java, JS, Ruby, TS (3.2K samples)

```powershell
# CodeT5 with language tokens (~10 min)
python src/models/train_binary_v2.py --model codet5 --tier tier3_shared --bf16
```

### Alternative: Orchestrator (trains ALL models for a tier automatically)

```powershell
# Dry run — see what will be trained (no GPU needed)
python src/models/run_phase1_all_tiers.py --dry-run

# Run all models for a specific tier
python src/models/run_phase1_all_tiers.py --only-tier tier1_c_cpp --bf16
python src/models/run_phase1_all_tiers.py --only-tier tier2_cpp --bf16
python src/models/run_phase1_all_tiers.py --only-tier tier2_python --bf16
python src/models/run_phase1_all_tiers.py --only-tier tier2_php --bf16
python src/models/run_phase1_all_tiers.py --only-tier tier3_shared --bf16
```

### Evaluate & Select Winners

```powershell
# Compare all models across all tiers
python src/evaluation/evaluate_binary_v2.py --compare-all

# Auto-select best model per tier
python src/evaluation/evaluate_binary_v2.py --select-winners

# View detailed results for a specific tier/model
python src/evaluation/evaluate_binary_v2.py --tier tier1_c_cpp --model codet5
```

### Check Results

```powershell
# Results JSONs
dir logs\phase1_*_v2.json
dir logs\phase1_*_zeroshot.json

# Winner checkpoints
dir models\saved\phase1_winner_*

# View manifest
python -m json.tool data\processed\manifest.json
```

---

## Phase 2 — CWE Multi-Class Classification (Multi-Tier)

> All models classify vulnerable code into 15 MITRE semantic groups using LoRA (r=64, alpha=128), Focal Loss (gamma=2.0), and WeightedRandomSampler.

### Option A: Automated Multi-Tier Orchestrator

```powershell
# Dry run — inspect full 11-run execution plan without training
python src/models/run_phase2_all_tiers.py --dry-run

# Run full pipeline across all tiers on CUDA
python src/models/run_phase2_all_tiers.py --bf16 --epochs 15

# Run a specific tier only
python src/models/run_phase2_all_tiers.py --only-tier tier1_c_cpp --bf16
python src/models/run_phase2_all_tiers.py --only-tier tier2_python --bf16
python src/models/run_phase2_all_tiers.py --only-tier tier2_cpp --bf16
python src/models/run_phase2_all_tiers.py --only-tier tier2_php --bf16
python src/models/run_phase2_all_tiers.py --only-tier tier3_shared --bf16
```

### Option B: Step-by-Step Training

```powershell
# ── TIER 1: C/C++ (High Resource — 51K CWE samples) ──
# 1. Train CodeT5-v2
python src/models/train_cwe.py --model codet5 --tier tier1_c_cpp --variant-tag v2 --bf16 --epochs 15 --batch-size 16 --max-length 512

# 2. Train GraphCodeBERT-v2
python src/models/train_cwe.py --model graphcodebert --tier tier1_c_cpp --variant-tag v2 --bf16 --epochs 15 --batch-size 16 --max-length 512

# 3. Train CodeBERT-MOO-v2 (AIBugHunter multi-objective optimization adaptation)
python src/models/train_codebert_moo.py --tier tier1_c_cpp --bf16 --epochs 10 --batch-size 16 --max-length 512

# 4. Evaluate Fixed & Calibrated Ensemble (solves ensemble-v2 underperformance)
python src/models/train_cwe.py --ensemble --variant-tag v2

# 5. Compare Tier 1 variants & print % improvement over v1 baseline
python src/models/train_cwe.py --compare

# ── TIER 2: Per-Language (Medium Resource — warm-started from Tier 1 winner) ──
# C++ (5.2K samples)
python src/models/train_cwe.py --model graphcodebert --tier tier2_cpp --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model codet5 --tier tier2_cpp --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15

# Python (808 samples)
python src/models/train_cwe.py --model graphcodebert --tier tier2_python --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model codet5 --tier tier2_python --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15

# PHP (1.9K samples)
python src/models/train_cwe.py --model codet5 --tier tier2_php --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model graphcodebert --tier tier2_php --warm-start models/saved/phase1_winner_tier1_c_cpp --variant-tag v2 --bf16 --epochs 15

# ── TIER 3: Shared Multilingual (Go, Java, JS, Ruby, TS — <LANG=xx> tokens) ──
python src/models/train_cwe.py --model codet5 --tier tier3_shared --use-lang-tokens --variant-tag v2 --bf16 --epochs 15
python src/models/train_cwe.py --model graphcodebert --tier tier3_shared --use-lang-tokens --variant-tag v2 --bf16 --epochs 15
```

### Phase 2 Evaluation & Benchmark

```powershell
# Print consolidated comparison table across ALL tiers
python src/evaluation/evaluate_cwe_v2.py --compare-all

# Inspect specific tier confusion matrix & per-class precision/recall/F1
python src/evaluation/evaluate_cwe_v2.py --tier tier1_c_cpp
python src/evaluation/evaluate_cwe_v2.py --tier tier2_python
python src/evaluation/evaluate_cwe_v2.py --tier tier2_php
python src/evaluation/evaluate_cwe_v2.py --tier tier3_shared

# Auto-select best model per tier and export to models/saved/phase2_winner_<tier>/
python src/evaluation/evaluate_cwe_v2.py --select-winners
```

---

## Phase 3 — Severity Scoring (CVSS 0–10 Regression, 3 Approaches)

> **Data:** 6,218 severity samples total (4,537 train / 839 val / 842 test).
> **Approaches:** A (single-task per-tier), B (DeepCVA multi-task), C (shared cross-tier).
> All models use SmoothL1Loss (Huber), LoRA r=64/alpha=128, sigmoid output × 10.

### Option A: Automated Orchestrator (all 12 runs)

```powershell
# Dry run — inspect full 12-run execution plan
python src/models/run_phase3_all_tiers.py --dry-run

# Full execution across all approaches and tiers (~6-8 hours)
python src/models/run_phase3_all_tiers.py --bf16 --epochs 15

# Only Approach A (per-tier single-task)
python src/models/run_phase3_all_tiers.py --only-approach A --bf16

# Only Approach B (multi-task)
python src/models/run_phase3_all_tiers.py --only-approach B --bf16

# Only Approach C (shared cross-tier)
python src/models/run_phase3_all_tiers.py --only-approach C --bf16

# Only a specific tier
python src/models/run_phase3_all_tiers.py --only-tier tier1_c_cpp --bf16
```

### Option B: Step-by-Step Training

```powershell
# ── APPROACH A: Single-task severity regression per tier ──

# Tier 1: C/C++ (1,842 severity samples, ~1 hour each)
python src/models/train_severity.py --approach A --model codet5 --tier tier1_c_cpp --bf16 --epochs 15
python src/models/train_severity.py --approach A --model graphcodebert --tier tier1_c_cpp --bf16 --epochs 15

# Tier 2: C++ (269 samples, warm-started, ~15 min)
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_cpp --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp

# Tier 2: Python (265 samples, warm-started, ~15 min)
python src/models/train_severity.py --approach A --model graphcodebert --tier tier2_python --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp

# Tier 2: PHP (892 samples, warm-started, ~30 min)
python src/models/train_severity.py --approach A --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp

# Tier 3: Shared with <LANG=xx> tokens (1,269 samples, ~45 min)
python src/models/train_severity.py --approach A --model codet5 --tier tier3_shared --bf16 --use-lang-tokens

# ── APPROACH B: DeepCVA multi-task (VF + CWE + Severity heads) ──

python src/models/train_severity.py --approach B --model graphcodebert --tier tier1_c_cpp --bf16
python src/models/train_severity.py --approach B --model graphcodebert --tier tier2_cpp --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach B --model codet5 --tier tier2_php --bf16 --warm-start models/saved/phase1_winner_tier1_c_cpp
python src/models/train_severity.py --approach B --model codet5 --tier tier3_shared --bf16 --use-lang-tokens

# ── APPROACH C: ONE shared cross-tier severity regressor ──

python src/models/train_severity.py --approach C --model codet5 --bf16
python src/models/train_severity.py --approach C --model graphcodebert --bf16
```

### Phase 3 Evaluation & Benchmark

```powershell
# Consolidated comparison table (all approaches, all tiers)
python src/models/train_severity.py --evaluate-all

# Full comparison with per-band breakdowns
python src/evaluation/evaluate_severity.py --compare-all

# Per-tier detailed breakdown
python src/evaluation/evaluate_severity.py --tier tier1_c_cpp
python src/evaluation/evaluate_severity.py --tier tier2_python
python src/evaluation/evaluate_severity.py --tier tier3_shared

# Per-tier vs shared comparison (central research question)
python src/evaluation/evaluate_severity.py --per-tier-vs-shared

# Auto-select best model per tier and export to models/saved/phase3_winner_<tier>/
python src/evaluation/evaluate_severity.py --select-winners
```

### Check Phase 3 Results

```powershell
# Results JSONs
dir logs\phase3_severity_results_*.json

# Winner checkpoints
dir models\saved\phase3_winner_*

# View consolidated winners
python -m json.tool logs\phase3_winners.json
```

---

## Phase 4 — LLM-Based Code Repair (Updated Commands)

> **CodeT5 fine-tuning works on BOTH Mac and Windows.**
> **Zero-shot ablation (Mistral/DeepSeek 4-bit) requires Windows CUDA only.**

### Option A: Automated Orchestrator

```powershell
# Dry run — see all 8 runs
python src/models/run_phase4_all.py --dry-run

# Full execution — all methods (~10-15 hours)
python src/models/run_phase4_all.py --bf16 --epochs 20

# Only shared model (PRIMARY)
python src/models/run_phase4_all.py --only-method shared --bf16

# Only per-tier ablation
python src/models/run_phase4_all.py --only-method per-tier --bf16

# Only zero-shot baselines (Windows CUDA only)
python src/models/run_phase4_all.py --only-method zero-shot
```

### Option B: Step-by-Step Training

```powershell
# ── PRIMARY: Shared CodeT5 (ALL languages pooled, 28K fix pairs) ──
python src/models/train_repair.py --method shared --bf16 --epochs 20

# ── ABLATION A: Per-Tier CodeT5 ──
python src/models/train_repair.py --method per-tier --tier tier1_c_cpp --bf16 --epochs 20
python src/models/train_repair.py --method per-tier --tier tier2_cpp --bf16 --epochs 20
python src/models/train_repair.py --method per-tier --tier tier2_python --bf16 --epochs 20
python src/models/train_repair.py --method per-tier --tier tier2_php --bf16 --epochs 20
python src/models/train_repair.py --method per-tier --tier tier3_shared --bf16 --epochs 20

# ── ABLATION B: Zero-Shot Baselines (CUDA only, 4-bit quantization) ──
python src/models/train_repair.py --method zero-shot --model-name mistral --max-samples 200
python src/models/train_repair.py --method zero-shot --model-name deepseek --max-samples 200
```

### Phase 4 Evaluation

```powershell
# Compare all methods side by side
python src/evaluation/evaluate_repair.py --compare-all

# Generate 50 samples per method for manual review
python src/evaluation/evaluate_repair.py --manual-review 50

# Evaluate specific prediction file
python src/evaluation/evaluate_repair.py --predictions-file logs/phase4_predictions_shared_all_codet5.json
```

### Check Phase 4 Results

```powershell
# Results JSONs
dir logs\phase4_repair_results_*.json

# Predictions
dir logs\phase4_predictions_*.json

# Saved models
dir models\saved\phase4_*

# Comparison report
type results\phase4_code_repair_results.md
```

---

## Phase 5 — Streamlit App (Either Machine)

```powershell
# Run full end-to-end integration test suite
python tests/test_phase5_pipeline.py

# Launch interactive Streamlit web dashboard
streamlit run app/main.py
```

---

## Phase 6 — Evaluation, Ablations & Report Artifacts

```powershell
# Run all Phase 6 ablations and export consolidated metrics summary
python src/evaluation/run_phase6_evaluations.py

# Inspect consolidated evaluation summary
Get-Content results\phase6_evaluation_summary.json
```

---

## Phase 7 — Stretch Goals: Self-Verification Loop & Line Explainability

```powershell
# Benchmark Option B (Self-Verification Loop) & Option C (Attention Line Attribution)
python src/evaluation/run_phase7_evaluations.py

# Inspect Phase 7 metrics & benchmark summary
Get-Content results\phase7_evaluation_summary.json

# Launch Streamlit UI with interactive Self-Verification badges & Attention Heatmaps
streamlit run app/main.py
```

---

## 🔧 Utility Commands

### Mac

```bash
python -c "import torch; print(f'MPS available: {torch.backends.mps.is_available()}')"
cat data/processed/manifest.json | python -m json.tool
ls -lh models/saved/
rm -rf ~/.cache/huggingface/hub/
```

### Windows

```powershell
nvidia-smi
nvidia-smi -l 2
python -c "import torch; print(f'CUDA: {torch.version.cuda}, GPU: {torch.cuda.get_device_name(0)}')"
python -c "import torch; t=torch.cuda.get_device_properties(0).total_mem; f=torch.cuda.mem_get_info()[0]; print(f'Free: {f/1e9:.1f} GB / {t/1e9:.1f} GB')"
python -m json.tool data\processed\manifest.json
dir models\saved\
Get-Content logs\train_tier1_c_cpp_codet5_v2.log -Tail 50
Remove-Item -Recurse -Force $env:USERPROFILE\.cache\huggingface\hub\
```

---

## 📦 Copy Results Back to Mac

After training on Windows, copy these files back:

```
logs/phase1_*_results_v2.json          # Phase 1 result JSONs
logs/phase1_*_zeroshot.json            # VulBERTa zero-shot
logs/phase1_winners_v2.json            # Phase 1 consolidated winners
logs/phase1_orchestration_v2.json      # Phase 1 orchestration summary
logs/phase2_cwe_results_*.json         # Phase 2 result JSONs
logs/phase2_winners_v2.json            # Phase 2 consolidated winners
logs/phase3_severity_results_*.json    # Phase 3 result JSONs
logs/phase3_winners.json               # Phase 3 consolidated winners
logs/phase4_repair_results_*.json      # Phase 4 result JSONs
logs/phase4_predictions_*.json         # Phase 4 predictions (for evaluation)
models/saved/phase1_winner_*/          # Phase 1 winner checkpoints (~2-5 MB each)
models/saved/phase2_winner_*/          # Phase 2 winner checkpoints
models/saved/phase3_A_*/              # Phase 3 Approach A checkpoints
models/saved/phase4_*/                 # Phase 4 repair model checkpoints
data/processed/manifest.json           # Tier assignments & counts
results/                               # All result files
```
