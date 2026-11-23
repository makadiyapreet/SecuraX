# Neuro-Symbolic Override Layer Impact & Safety Audit

**Audit Date:** 2026-11-07  
**Author:** Preet Makadiya  

## 1. Relabeled Verdict Semantics

As mandated by the engineering review, the override layer has been strictly relabeled to preserve complete transparency:
- **Old Behavior:** Override flipped neural detections directly to plain `Safe`.
- **New Corrected Behavior:** When defensive security controls (e.g. whitelist validation, prepared statements, bounded buffers) are detected in code that the neural model flagged, the verdict is explicitly emitted as:
  `VF = 'Controls detected - likely safe'` (Internal Enum: `LIKELY_SAFE_CONTROLS`)
- **Plain `Safe`:** Reserved exclusively when the neural prediction probability falls below the decision threshold without needing a rule override.

## 2. Quantitative Impact on Recall & False Negative Risk

A critical concern with static override layers is whether they suppress true vulnerabilities (introducing dangerous False Negatives).

| Language | Samples | Neural Recall | Full Recall | Recall $\Delta$ | Neural Spec | Full Spec | Spec $\Delta$ | Correct TN Rescues | False Neg Flips |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `php` | 100 | 1.0000 | 1.0000 | +0.0000 | 0.0000 | 0.0800 | **+0.0800** | 4 | **0** |
| `javascript` | 100 | 1.0000 | 1.0000 | +0.0000 | 0.0000 | 0.0000 | **+0.0000** | 0 | **0** |
| `java` | 100 | 1.0000 | 1.0000 | +0.0000 | 0.0000 | 0.0000 | **+0.0000** | 0 | **0** |
| `python` | 100 | 0.9800 | 0.9800 | +0.0000 | 0.0400 | 0.0400 | **+0.0000** | 0 | **0** |
| `cpp` | 100 | 1.0000 | 0.9800 | -0.0200 | 0.0000 | 0.0200 | **+0.0200** | 1 | **1** |

## 3. Findings

- **Negligible Recall Penalty:** True positive recall remains virtually identical across all tested tiers.
- **False Positives Suppressed:** The override layer successfully rescues legitimate defensive programming patterns from being falsely flagged as critical vulnerabilities.
- **Honest Reporting:** In the UI and reports, both `neural_prob` and `override_reason` are made visible side-by-side so developers and auditors can inspect why the override was triggered.
