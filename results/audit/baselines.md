# Baselines, Sample Sizes, and Uncertainty Audit

**Audit Date:** 2026-11-07  
**Author:** Preet Makadiya  

## 1. Phase 3 CVSS Severity Scoring: Neural vs. Naive Baselines

A critical question in vulnerability severity regression is whether fine-tuned neural representations outperform simple statistical baselines.

| Model / Baseline | MAE | RMSE | $R^2$ | Spearman $\rho$ | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Neural Head (GraphCodeBERT Tier 1) | 1.4472 | 1.8778 | -0.288 | -0.023 | |
| Global Train Mean Baseline (5.47) | 1.3500 | 1.7150 | 0.000 | 0.000 | |
| Global Train Median Baseline (5.00) | 1.3400 | 1.7300 | -0.018 | 0.000 | |
| Per-CWE Group Mean Baseline | 1.2800 | 1.6400 | 0.086 | 0.312 | |

### Honest Scientific Finding on Severity Regression:
- The neural regression head exhibits a noticeable regression-to-the-mean effect, predicting CVSS scores clustered in the 4.8–6.0 range.
- Predicting the Per-CWE group mean yields competitive MAE (1.28) and positive correlation (Spearman $\rho = 0.312$), indicating that code syntax alone carries limited CVSS severity signal without environment context (e.g., network attack vector vs local access).

## 2. Phase 4 Code Refinement: Sample Size and Evaluation Criteria

- **Sample Size ($N$):** In Phase 6 Ablation 5, detailed context ablation was conducted on $N=3$ functions across languages; automated syntax and static checks run on all $N=25$ vulnerable test bench fixtures.
- **Evaluator:** Automated validation via Python `ast`, PHP `-l`, GCC `-fsyntax-only`, Node `--check`, combined with author manual review.
- **Definition of Successful Refinement:** A patch is categorized as successful if and only if:
  1. The code parses without syntax errors.
  2. The specific vulnerable construct (e.g. `query = f'...'`) is neutralized (e.g. replaced with parameterized placeholders).
  3. Non-trivial code structure is preserved (minimum 50% edit similarity).
  4. The Phase 7 self-verification checks return 0 newly introduced critical flaws.

## 3. Phase 7 Option C Attention Explainability: Wilson Confidence Intervals

- **Sample Size:** $N = 10$ qualitative ground-truth audited functions.
- **Top-1 Attribution Accuracy:** 50.0% (95% Wilson CI: [23.7%, 76.3%])
- **Top-3 Attribution Accuracy:** 100.0% (95% Wilson CI: [72.2%, 100.0%])

> **Plausibility vs. Faithfulness Caveat:**
> Token attention pooling highlights tokens correlated with vulnerability classification during model pre-training. However, attention weights are not a formal proof of causal runtime execution. They should be interpreted as **plausible diagnostic saliency maps** rather than definitive causality.

## 4. Test Catalog Benchmark Breakdown (50 Cases)

- **Total Test Cases:** 50 (25 Vulnerable, 25 Safe)
- **Passing:** 48 / 50 (96.0%)
- **Warnings / Edge Cases:** 2 cases:
  1. `TC-V20` (C Race Condition): Classified as Uncertain due to absence of POSIX thread locks in local chunk.
  2. `TC-V22` (Python Insecure File Permissions): Flagged vulnerable under Path-Traversal/Input-Validation instead of pure CWE-732.
