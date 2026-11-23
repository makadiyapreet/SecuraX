# SecuraX Master Audit & Validation Changelog

**Date:** 2026-11-07  
**Author:** Preet Makadiya (B.Tech Minor Project)  
**Advisor / Guide:** [GUIDE_NAME], [INSTITUTE_NAME]  
**Branch:** `audit-fixes`  
**Execution Environment:** macOS Apple Silicon, Python 3.13.1, CPU-Only Inference  

---

## 1. Summary of Changes

This audit pass addressed validity, honesty, data leakage, and reporting issues identified during project review. In strict accordance with engineering constraints:
- **NO model retraining** was conducted. Existing neural weights (Phases 1–3) were preserved untouched.
- **CPU-Only Execution:** Enforced `torch.device("cpu")` to prevent Apple Silicon MPS sparse placeholder errors.
- **Honest Empirical Accounting:** All reported metrics originate from real evaluation scripts with zero fabricated figures.

---

## 2. Key Audit Deliverables & Results

### Item 0 — Workspace Preparation & Security Check
- Created git branch `audit-fixes`.
- Validated that `.env` is uncommitted and contains no leaked keys in repository history.
- Scrubbed absolute `file:///Users/...` URLs across all Markdown reports and documentation.
- Produced `results/audit/environment.json`.

### Item 5 — Data Leakage & Class Balance Audit
- Built `scripts/audit_leakage.py` checking exact duplicates, near-duplicates (Jaccard $\ge 0.9$), and CVE overlaps across all tiers.
- **Root-Cause Discovery on Tier 2 PHP & Tier 3 Shared:**
  - Evaluated splits in `tier2_php` ($N=291$) and `tier3_shared` ($N=449$) contain **100% vulnerable instances (`vul=1`, 0 safe)**.
  - Previous claims of 'perfect 1.000 F1 score in PHP' were clarified: precision is trivially 1.0 due to the absence of negative samples, and AUROC is mathematically undefined (`NaN`).
  - Saved outputs: `results/audit/leakage_report.csv`, `results/audit/leakage_report.md`, `results/audit/metrics_ci.csv`.

### Item 6 — Threshold Policy & Re-Selection
- Built `scripts/audit_thresholds.py` applying the formal rule:
  $$\theta^* = \arg\max_\theta \text{Recall}(\theta) \quad \text{subject to } \text{Precision} \ge P_{\text{floor}} \quad (P_{\text{floor}} = 0.30)$$
- **Reconciled Tier 1 Drop:** Revealed that Phase 1 v2 previously enforced an artificial $P \ge 0.75$ floor, dropping Recall to 45.8%. Selecting $\theta = 0.20$ restores Recall to **80.90%** (+35.1% gain).
- Gated new threshold profiles behind `config/threshold_policy.yaml` (`use_validation_thresholds: false`).
- Saved outputs: `results/audit/thresholds.csv`, `docs/audit/thresholds.md`.

### Item 7 — 1-to-1 CWE Taxonomy Mapping
- Resolved duplicate mappings in `src/data/cwe_taxonomy.py`:
  - `CWE-125` $\to$ `OOB-Read`
  - `CWE-787` and `CWE-124` $\to$ `OOB-Write`
- Added comprehensive unit tests in `tests/unit/test_cwe_taxonomy.py` (5/5 passed).
- Built `scripts/audit_phase6_gains.py` reconciling Phase 6 ablation gains (+49.8% Recall, +114.6% F1).
- Saved outputs: `results/audit/cwe_duplicates.csv`, `results/audit/cwe_eval_old_vs_new.csv`.

### Item 8 — Baselines and Uncertainty Quantification
- Built `scripts/audit_baselines.py` implementing naive baselines for Phase 3 CVSS Severity (Mean = 5.47, Median = 5.00, Per-CWE Mean = 1.28 MAE).
- Computed 95% Wilson confidence intervals for Phase 7 Option C Attention Explainability (Top-1: 50.0% [23.7%, 76.3%]; Top-3: 100.0% [72.2%, 100.0%]).
- Documented 50-fixture benchmark confusion matrix (48/50 passed, 96.0%).
- Saved outputs: `results/audit/benchmark_breakdown.csv`, `results/audit/baselines.md`.

### Item 3 — Held-Out Real-World Evaluation (CVEFixes)
- Built `scripts/build_heldout.py` creating 250 real-world before/after commit pairs (500 functions) across 5 languages (PHP, Python, CPP, JavaScript, Java), strictly verifying 0 training hash leakage.
- Built `scripts/eval_heldout.py` evaluating Neural Only, Full System (override ON), and Override Only.
- Saved outputs: `results/audit/heldout_{lang}.csv`, `results/audit/heldout_summary.md`, and cached predictions under `results/audit/preds/`.

### Item 2 — Relabeled Neuro-Symbolic Override Layer
- Relabeled rule-defended outputs in `src/pipeline/securax_pipeline.py` and `src/pipeline/model_manager.py`:
  - `VF = 'Controls detected - likely safe'` (Internal enum `LIKELY_SAFE_CONTROLS`).
  - Plain `Safe` reserved exclusively when the neural model score $< \text{threshold}$ and no override fired.
  - Transparently preserved `neural_prob`, `override_reason`, and `override_applied`.
- Added unit tests in `tests/unit/test_override_label.py` (3/3 passed).
- Measured false-negative risk via `scripts/audit_override_impact.py`: only 1 FN flip across 500 samples (negligible recall impact, high precision rescue).
- Saved outputs: `results/audit/override_impact.csv`, `docs/audit/override_impact.md`.

### Item 4 — Claim Rewording and Documentation Cleanliness
- Replaced marketing terms with measured scientific statements.
- Added language matrix distinguishing trained neural tiers vs supported parsers in `results/audit/language_counts.csv`.

### Item 10 — Groq Hosted Model Verification
- Verified Groq hosted API connectivity using dual failover keys via `scripts/verify_groq_model.py`.
- Confirmed `qwen/qwen3.8-27b` is active and operational (`results/audit/groq_models.json`).

---

## 3. Deviations from Original Plan

| Proposed in Initial Plan | Audited Reality | Resolution / Status |
| :--- | :--- | :--- |
| Pure Neural 100% Accuracy in PHP | Single-class testbed (all vul=1) | Honestly documented; held-out CVEFixes evaluation added. |
| Automatic retraining of Phase 1 | Hard constraint: NO RETRAINING | Evaluated inference only; sweep re-selection under $P_{floor}=0.30$. |
| Rule override returned plain "Safe" | Concealed neural detection | Relabeled to `Controls detected - likely safe` with full transparency. |

*Mentor approval:* `PENDING CONFIRMATION`

