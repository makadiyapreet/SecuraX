# SecuraX — Model Results Summary

This folder contains a consolidated view of all trained model results and evaluation benchmarks across phases.

---

## 📁 Folder Structure

```
results/
├── README.md                                       # This file — consolidated cross-phase benchmark dashboard
├── phase0_5_audit_results.md                       # Phase 0.5: Data audit & tiering across datasets
├── phase1_binary_detection_results.md              # Phase 1: Multi-tier binary VF detection
├── phase2_cwe_classification_results.md            # Phase 2: Multi-tier CWE-15 classification
├── phase3_severity_scoring_results.md              # Phase 3: Multi-tier CVSS severity scoring (Approach A)
├── phase4_code_repair_results.md                   # Phase 4: Groq LLM-based code refinement benchmark
├── phase4_manual_review.md                         # Phase 4: Qualitative manual inspection report (40+ samples)
├── phase1_binary_detection_old/                    # Phase 1 v1 (single-tier, archived)
│   ├── SUMMARY.md
│   ├── codet5_results.json
│   ├── graphcodebert_results.json
│   └── comparison.json
└── phase2_cwe_classification_old/                  # Phase 2 v1 (24-class, archived)
    ├── SUMMARY.md
    ├── cwe_results.json
    └── cwe_label_map.json
```

---

## Models Overview Across Phases

| Tier / Language | Phase | Task | 🏆 Winner Backbone | Checkpoint / Provider |
|---|---|---|---|---|
| Tier 1 (C/C++) | Phase 1 | Binary VF Detection | **GraphCodeBERT** + LoRA | `models/saved/phase1_winner_tier1_c_cpp/` |
| Tier 2 (C++) | Phase 1 | Binary VF Detection | **GraphCodeBERT** + LoRA | `models/saved/phase1_winner_tier2_cpp/` |
| Tier 2 (Python) | Phase 1 | Binary VF Detection | **GraphCodeBERT** + LoRA | `models/saved/phase1_winner_tier2_python/` |
| Tier 2 (PHP) | Phase 1 | Binary VF Detection | **CodeT5** + LoRA | `models/saved/phase1_winner_tier2_php/` |
| Tier 3 (Shared) | Phase 1 | Binary VF Detection | **CodeT5** + LoRA + `<LANG=xx>` | `models/saved/phase1_tier3_shared_codet5/` |
| Tier 1 (C/C++) | Phase 2 | 15-Class CWE Classification | **Calibrated Ensemble** ($w=0.65, T=1.5$) | `models/saved/phase2_winner_tier1_c_cpp/` |
| Tier 2 (C++) | Phase 2 | 15-Class CWE Classification | **GraphCodeBERT-v2** | `models/saved/phase2_winner_tier2_cpp/` |
| Tier 2 (Python) | Phase 2 | 15-Class CWE Classification | **GraphCodeBERT-v2** | `models/saved/phase2_winner_tier2_python/` |
| Tier 2 (PHP) | Phase 2 | 15-Class CWE Classification | **CodeT5-v2** | `models/saved/phase2_winner_tier2_php/` |
| Tier 3 (Shared) | Phase 2 | 15-Class CWE Classification | **CodeT5-v2** + `<LANG=xx>` | `models/saved/phase2_winner_tier3_shared/` |
| Tier 1 (C/C++) | Phase 3 | CVSS Severity (0–10) | **CodeT5** Regressor | `models/saved/phase3_A_tier1_c_cpp_codet5/` |
| Tier 2 (C++) | Phase 3 | CVSS Severity (0–10) | **GraphCodeBERT** Regressor | `models/saved/phase3_A_tier2_cpp_graphcodebert/` |
| Tier 2 (Python) | Phase 3 | CVSS Severity (0–10) | **GraphCodeBERT** Regressor | `models/saved/phase3_A_tier2_python_graphcodebert/` |
| Tier 2 (PHP) | Phase 3 | CVSS Severity (0–10) | **CodeT5** Regressor | `models/saved/phase3_A_tier2_php_codet5/` |
| **Cross-Language** (All) | **Phase 4** | **Automated Code Refinement** | **`qwen/qwen3.8-27b`** | **Groq LPU API** (`config/refinement.yaml`) |

---

## Quick Results Summary

### Phase 1 — Multi-Tier Binary Vulnerability Detection

| Tier | Language(s) | 🏆 Winner | Opt. Thr | Test Recall | Test F1 | Test Accuracy |
|---|---|---|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **GraphCodeBERT** | 0.70 | 0.4580 | **0.5703** | 0.9262 |
| **Tier 2** | C++ | **GraphCodeBERT** | 0.10 | 0.9949 | **0.9843** | 0.9776 |
| **Tier 2** | PHP | **CodeT5** | 0.10 | 1.0000 | **1.0000** | 1.0000 |
| **Tier 2** | Python | **GraphCodeBERT** | 0.15 | 0.8545 | **0.8174** | 0.9729 |
| **Tier 3** | Shared | **CodeT5** | 0.50 | 0.8412 | **0.8330** | 0.9410 |

→ Full details: [`phase1_binary_detection_results.md`](./phase1_binary_detection_results.md)

---

### Phase 2 — Multi-Tier CWE Multi-Class Classification (15 MITRE Semantic Groups)

| Tier | Language(s) | 🏆 Winner | Macro-Recall | Macro-F1 | Accuracy |
|---|---|---|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **Calibrated Ensemble** | **0.6513** | **0.6894** | 0.6895 |
| **Tier 2** | C++ | **GraphCodeBERT-v2** | 0.8339 | **0.7568** | 0.8355 |
| **Tier 2** | Python | **GraphCodeBERT-v2** | 0.5180 | **0.4777** | 0.8438 |
| **Tier 2** | PHP | **CodeT5-v2** | 0.6703 | **0.6231** | 0.9617 |
| **Tier 3** | Shared | **CodeT5-v2** | 0.8307 | **0.6866** | 0.8369 |

→ Full details: [`phase2_cwe_classification_results.md`](./phase2_cwe_classification_results.md)

---

### Phase 3 — Multi-Tier CVSS Severity Scoring (Regression 0–10)

Approach A (per-tier single-task regression) evaluated on real CVE/BigVul test sets:

| Tier | Language(s) | 🏆 Winner | Val MAE | Test MAE | Test RMSE | Band Acc |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | **CodeT5** | 1.384 | **1.357** | 1.777 | **67.66%** |
| **Tier 2** | C++ | **GraphCodeBERT** | 1.288 | **1.499** | 2.038 | **68.42%** |
| **Tier 2** | Python | **GraphCodeBERT** | 0.941 | **1.269** | 1.643 | **73.53%** |
| **Tier 2** | PHP | **CodeT5** | 1.040 | **1.167** | 1.454 | **68.26%** |
| **Tier 3** | Shared | **CodeT5** | **1.200** | — | — | — |

> **Key finding:** Best overall severity predictor is Tier 2 PHP CodeT5 (MAE = 1.167). Continuous CVSS prediction is bounded by mean regression around ~5.38 CVSS points; Medium band accuracy reaches ~73%.

→ Full details: [`phase3_severity_scoring_results.md`](./phase3_severity_scoring_results.md)

---

### Phase 4 — LLM-Based Automated Code Refinement (Groq API)

> **Constraint Exception Note:** Groq serves open-weight LLMs via a high-throughput hosted API (LPUs). This provides rapid inference on any machine (macOS, Linux, Windows) with zero local GPU requirement, but relies on a free-tier cloud service subject to rate limits and API terms.

#### 1. Model Comparison: Default vs Alternate Model

Evaluated on stratified real fix pairs from BigVul and CVEFixes across 8+ programming languages:

| Metric Category | Evaluation Metric | `qwen/qwen3.8-27b` (Default ⭐) | `openai/gpt-oss-120b` (Alternate) | Delta |
|---|---|:---:|:---:|:---:|
| **Ground-Truth** | **Perfect Prediction (PP)** | **0.0%** | 0.0% | 0.0% |
| **Ground-Truth** | **Exact Match (EM)** | **0.0%** | 0.0% | 0.0% |
| **Ground-Truth** | **Levenshtein Edit Similarity** | **0.472** | 0.176 | **+0.296** |
| **Ground-Truth** | **Token BLEU-4** | **32.8** | 11.3 | **+21.5** |
| **Proxy Quality** | **Syntactic Validity** | **40.0%** | 25.0% | **+15.0%** |
| **Proxy Quality** | **Detector Flip Rate (VF Flip)** | **30.0%** | 5.0% | **+25.0%** |
| **Operational** | **Avg Latency per Snippet** | **5.51s** | 7.94s | **-2.43s (Faster)** |

#### 2. Manual Qualitative Review (40+ Samples)
- **Fixed (Secure & Functional):** **77.5% (31/40)** — Accurately injects parameterization, bounds checks, and pointer validation.
- **Partial Fix:** **20.0% (8/40)** — Addresses the primary weakness but misses secondary paths or edge validation.
- **Broke Behavior:** **2.5% (1/40)** — Injected syntax or structural issue.
- **Unchanged:** **0.0% (0/40)**.

#### 3. API Resilience & Multi-Key Failover
- **Automatic Fallback Rotation:** If the primary `GROQ_API_KEY` exhausts credits, hits a 429 rate limit, or encounters token ceilings, the client automatically transfers requests to `GROQ_API_KEY_FALLBACK` (or additional keys in pool) transparently.
- **Persistent Cache:** Exact prompt requests are stored as SHA-256 hashes in `data/cache/groq/`, reducing API cost and latency to ~0ms on repeat requests.
- **Offline / Graceful Fallback:** If all keys are unavailable, the system safely returns `refinement_unavailable` without crashing the downstream pipeline.

→ Full benchmark comparison: [`phase4_code_repair_results.md`](./phase4_code_repair_results.md)  
→ Qualitative inspection breakdown: [`phase4_manual_review.md`](./phase4_manual_review.md)

---

## Reference Documentation

| Phase | Architecture Document | Results & Analysis |
|---|---|---|
| Phase 0 | [`docs/PHASE_0.md`](../docs/PHASE_0.md) | — |
| Phase 0.5 | [`docs/PHASE_0.5.md`](../docs/PHASE_0.5.md) | [`phase0_5_audit_results.md`](./phase0_5_audit_results.md) |
| Phase 1 | [`docs/PHASE_1.md`](../docs/PHASE_1.md) | [`phase1_binary_detection_results.md`](./phase1_binary_detection_results.md) |
| Phase 2 v1 (superseded) | [`docs/PHASE_2_v1_superseded.md`](../docs/PHASE_2_v1_superseded.md) | (archived in `phase2_cwe_classification_old/`) |
| Phase 2 v2 (active) | [`docs/PHASE_2.md`](../docs/PHASE_2.md) | [`phase2_cwe_classification_results.md`](./phase2_cwe_classification_results.md) |
| Phase 3 | [`docs/PHASE_3.md`](../docs/PHASE_3.md) | [`phase3_severity_scoring_results.md`](./phase3_severity_scoring_results.md) |
| Phase 4 | [`docs/PHASE_4.md`](../docs/PHASE_4.md) | [`phase4_code_repair_results.md`](./phase4_code_repair_results.md), [`phase4_manual_review.md`](./phase4_manual_review.md) |
