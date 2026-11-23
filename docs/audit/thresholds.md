# Decision Threshold Selection and Policy Audit

**Audit Date:** 2026-11-07  
**Author:** Preet Makadiya  

## 1. Threshold Selection Rule

In binary vulnerability triage, missing a real vulnerability (False Negative) is significantly more hazardous than flagging a questionable pattern for developer review (False Positive). Consequently, the primary evaluation metric is **Recall**.

We formalized the validation selection rule:
$$\theta^* = \arg\max_{\theta} \text{Recall}(\theta) \quad \text{subject to } \text{Precision}(\theta) \ge P_{\text{floor}}$$

Where $P_{\text{floor}} = 0.30$ (configured in `config/threshold_policy.yaml`).

## 2. Comparison Table: Production Default vs. Recall-Optimized

| Tier | Model | Default $\theta$ | Default Rec | Default Prec | Default F1 | New $\theta$ ($P_{floor}=0.30$) | New Rec | New Prec | New F1 | Recall $\Delta$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `tier1_c_cpp` | `graphcodebert` | 0.7 | 0.4580 | 0.7557 | 0.5703 | **0.2** | **0.8090** | 0.3020 | 0.4398 | **+0.3510** |
| `tier2_cpp` | `graphcodebert` | 0.1 | 0.9949 | 0.9739 | 0.9843 | **0.1** | **0.9949** | 0.9739 | 0.9843 | **+-0.0000** |
| `tier2_php` | `codet5` | 0.1 | 1.0000 | 1.0000 | 1.0000 | **0.1** | **1.0000** | 1.0000 | 1.0000 | **+0.0000** |
| `tier2_python` | `graphcodebert` | 0.15 | 0.8545 | 0.7833 | 0.8174 | **0.1** | **0.8636** | 0.7252 | 0.7884 | **+0.0091** |

## 3. Investigation: Reconciling the Tier 1 Performance Drop

A critical discrepancy identified in the review was the apparent drop in Tier 1 C/C++ metrics from:
- **Phase 1 v1:** AUROC 0.9087, F1 0.6827  
- **Phase 1 v2:** AUROC 0.8833, F1 0.5703, Recall 0.4580 (at $\theta = 0.70$)  

### Root-Cause Resolution:
1. **Strict Multi-Dataset Benchmarking:** Phase 1 v1 was evaluated on a smaller, synthetic-heavy subset (BigVul only). Phase 1 v2 expanded to a 445,000+ multi-source benchmark combining DiverseVul, BigVul, MegaVul, and CVEFixes with strict stratified splits.
2. **Artificial Precision Floor Constraint:** In Phase 1 v2, the threshold selection was locked to $\theta = 0.70$ because a strict high-precision floor ($P \ge 0.75$) was applied. This constrained the model to ultra-high confidence predictions, dropping Recall to 45.8%.
3. **Recall Recovery:** When relaxing $P_{floor}$ to the realistic security operational baseline of 0.30, $\theta = 0.20$ yields **80.90% Recall** (+35.1% absolute gain) with F1 of 0.4398.

## 4. Architectural Safety & Flag-Gated Deployment

To prevent breaking existing tested workflows, all model weights and default configurations remain unchanged. The new threshold profile is controlled via the configuration toggle:
```yaml
use_validation_thresholds: false  # Change to true to activate recall-optimized profile
```
