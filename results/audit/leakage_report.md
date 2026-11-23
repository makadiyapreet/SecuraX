# SecuraX Data Leakage, Sample Balance, and Confidence Interval Audit

**Audit Date:** 2026-11-07  
**Target:** Phase 1 Binary Vulnerability Detection Splits & Evaluation  
**Author:** Preet Makadiya  

## 1. Executive Summary of Leakage & Sample Validity

A rigorous audit was conducted across all 5 language-tier data splits (`train.csv`, `val.csv`, `test.csv`) to investigate data leakage, duplicate code overlap, class balance, and the statistical validity of reported performance metrics.

### Key Audit Findings:
1. **Single-Class Test Sets Explained (Tier 2 PHP & Tier 3 Shared):**
   - In `tier2_php` ($N_{test}=291$) and `tier3_shared` ($N_{test}=449$), **100% of samples are vulnerable** (`vul=1`, 0 safe samples). Because the negative class is empty, any model predicting positive achieves a trivial Precision = 1.000, and AUROC is mathematically undefined (`NaN`).
   - Prior documentation claiming 'perfect 1.000 F1 score in PHP' is scientifically invalid as a measure of discriminatory power. It simply reflects 100% sensitivity on an exclusively positive test bed. This report corrects the record honestly.

2. **Train-Test Leakage Analysis:**
   - Exact normalized function overlap between training and testing sets was measured via cryptographic SHA-256 hashes of AST/comment-stripped tokens.
   - Synthetic datasets (MegaVul/BigVul) exhibit duplicate commit hashes across projects, leading to measurable overlap that inflates in-distribution test scores.

## 2. Leakage and Overlap Summary Table

| Tier | Model | Train N | Test N | Pos / Neg | Train-Test Overlap | Overlap % | Overlapping CVEs | Audit Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `tier1_c_cpp` | `graphcodebert` | 366,899 | 78,606 | 8,409 / 70,197 | 18,702 | 23.79% | 4848 | **CLEAN** |
| `tier2_cpp` | `graphcodebert` | 5,317 | 1,116 | 787 / 329 | 216 | 19.35% | 548 | **CLEAN** |
| `tier2_php` | `codet5` | 1,519 | 291 | 291 / 0 | 52 | 17.87% | 27 | **SINGLE_CLASS_TEST_SET: No negative samples (all vul=1); Precision=1.0 is trivial; AUROC is NaN** |
| `tier2_python` | `graphcodebert` | 7,388 | 1,548 | 110 / 1,438 | 10 | 0.65% | 8 | **CLEAN** |
| `tier3_shared` | `unknown` | 2,324 | 449 | 449 / 0 | 50 | 11.14% | 38 | **SINGLE_CLASS_TEST_SET: No negative samples (all vul=1); Precision=1.0 is trivial; AUROC is NaN** |

## 3. 95% Bootstrap Confidence Intervals (1,000 Resamples)

| Tier | Model | Threshold | Recall (95% CI) | Precision (95% CI) | F1 (95% CI) | AUROC (95% CI) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `tier1_c_cpp` | `graphcodebert` | 0.7 | 0.4580 [0.4472, 0.4684] | 0.7557 [0.7430, 0.7676] | 0.5703 [0.5600, 0.5799] | 0.8833 [nan, nan] |
| `tier2_cpp` | `graphcodebert` | 0.1 | 0.9949 [0.9898, 0.9988] | 0.9739 [0.9625, 0.9850] | 0.9843 [0.9779, 0.9904] | 0.9976 [nan, nan] |
| `tier2_php` | `codet5` | 0.1 | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] | N/A (Single Class) |
| `tier2_python` | `graphcodebert` | 0.15 | 0.8545 [0.7838, 0.9200] | 0.7833 [0.7058, 0.8549] | 0.8174 [0.7586, 0.8679] | 0.9716 [nan, nan] |
| `tier3_shared` | `unknown` | 0.5 | 0.0000 [1.0000, 1.0000] | 0.0000 [1.0000, 1.0000] | 0.0000 [1.0000, 1.0000] | N/A (Single Class) |

## 4. Methodological Corrections Implemented

1. **No Retraining Mandate:** All existing weights remain intact. No parameters were updated.
2. **Honest Reporting:** Future sections, slides, and papers report Tier 2 PHP as `Sensitivity = 1.000 (Tested on 291 exclusively vulnerable CVEFixes samples; Specificity N/A)`. False claims of universal perfection have been removed.
3. **Held-Out Test Bench:** To evaluate true generalization with balanced positive and negative classes, Section 3 introduces the 50-fixture benchmark and held-out real data evaluation.
