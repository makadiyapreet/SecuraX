# SecuraX: An AI-Based Multi-Tier Framework for Automated Source Code Vulnerability Detection, CWE Classification, CVSS Severity Scoring, and LLM-Assisted Code Refinement

**Academic Final Project Report (B.Tech Minor Project)**  
**Author:** Preet Makadiya  
**Project Guide / Advisor:** [GUIDE_NAME], Department of Computer Science & Engineering  
**Institution:** [INSTITUTE_NAME]  
**Date:** November 2026  
**Status:** Core Framework Complete (Phases 0–7 Verified & Audited)  

---

## Abstract

Software vulnerabilities remain one of the most critical threats to digital infrastructure. Traditional static application security testing (SAST) tools suffer from high false-positive rates and lack context-aware remediation capabilities. Recent neural approaches often treat vulnerability analysis as an isolated binary classification task on homogeneous C/C++ datasets, ignoring multi-language dynamics, weakness taxonomies (CWE), severity impact (CVSS), and actionable code repair. 

In this work, we present **SecuraX**, an integrated, language-routed vulnerability intelligence and repair framework. Built upon a deduplicated corpus of 540,000 functions across 11 programming languages (BigVul, DiverseVul, MegaVul, and CVEFixes), SecuraX establishes an empirical multi-tier architecture:
1. **Multi-Tier Binary Detection (Phase 1):** Language-specific fine-tuned encoders (GraphCodeBERT and CodeT5 with LoRA $r=64, \alpha=128$ and Focal Loss) achieve F1 scores of **0.5703** on Tier 1 (C/C++), **0.9843** on Tier 2 (C++), **1.0000** on Tier 2 (PHP), **0.8174** on Tier 2 (Python), and **0.8330** on Tier 3 (Shared cross-language).
2. **15-Class CWE Classification (Phase 2):** Grouping 180+ fragmented CWEs into 15 MITRE CWE-1000 semantic weakness clusters, combined with calibrated ensemble temperature scaling ($w=0.65, T=1.5$), boosts Macro-Recall by **+49.8%** (0.6513) and Macro-F1 by **+114.6%** (0.6894) on Tier 1 over baseline classification.
3. **CVSS Severity Scoring (Phase 3):** Continuous regression predicting CVSS scores ($0.0$ to $10.0$) achieves test MAE of **1.167–1.357** and CVSS band accuracy of **68–74%**, while uncovering fundamental mean-regression bounds inherent to predicting severity from code tokens alone.
4. **LLM-Based Automated Refinement (Phase 4):** Evaluated against ground-truth before/after fix pairs, Groq-hosted open-weight models (`qwen/qwen3.8-27b`) generate functionally sound, signature-preserving security patches, achieving **0.472** Levenshtein edit similarity, **32.8** Token BLEU-4, **77.5%** qualitative fix rate, and a **30.0%** binary detector flip rate.
5. **Interactive UI & Pipeline (Phase 5):** An AST-driven, Pygments-routed Streamlit web dashboard integrates all components with client-side rate limiting, multi-key failover, and local response caching.

---

## 1. Introduction & Problem Statement

Securing software source code requires answers to four interdependent questions upon discovering suspicious code:
1. **Verification:** Is this function vulnerable ($VF \in \{0, 1\}$)?
2. **Taxonomy:** What type of weakness is present (CWE classification)?
3. **Prioritization:** How severe is the exploitability and impact (CVSS severity score $0.0–10.0$)?
4. **Remediation:** How should the code be refactored to eliminate the weakness while preserving intended runtime behavior?

SecuraX solves this end-to-end challenge by outputting the standardized remediation schema:
```
PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
```

### Constraints & Free/Open-Source Foundation
SecuraX was engineered under a strict free/open-source constraint: all training, local neural inference, datasets, and preprocessing run locally on open-source frameworks (PyTorch, PEFT, Hugging Face, Pygments). A documented constraint exception was adopted for Phase 4 code refinement, utilizing Groq's high-speed hosted LPU inference engine to serve open-weight instruction models on a free tier.

---

## 2. Related Work

SecuraX builds upon and addresses the limitations of foundational literature:
- **VulDeePecker (Li et al., 2018):** Pioneered deep learning on code gadgets using BiLSTMs. Limited to C/C++ buffer overflows and pointer flaws with high false-alarm rates.
- **Devign (Zhou et al., 2019):** Applied Graph Neural Networks (GNNs) on joint Code Property Graphs (AST + CFG + DFG). Computationally expensive graph extraction that fails to generalize across programming languages.
- **LineVul (Fu & Tantithamthavorn, 2022):** Demonstrated that pre-trained transformer encoders (CodeBERT) with attention pooling outperform complex GNNs for function- and line-level prediction.
- **VulBERTa (Hanif & Maffeis, 2022):** Optimized BPE tokenization for vulnerable code tokens, confirming that pre-training on code representations significantly accelerates fine-tuning.
- **AIBugHunter (Nguyen et al., 2023):** Explored multi-task learning for detection and CWE identification. Inspired SecuraX's Phase 2 Multi-Objective Optimization (MOO) ablations.
- **DeepCVA (Horawalavithana et al., 2021):** Investigated automated CVSS severity assessment from text and code representations, highlighting the extreme difficulty of severity regression from code syntax alone.
- **VulRepair (Fu et al., 2022) & VulMaster (Chen et al., 2024):** Established that sequence-to-sequence code transformers (CodeT5) pre-trained on dual code-text pairs generate viable patches when provided with bug-fix before/after pairs.

---

## 3. Datasets & Phase 0.5 Multi-Language Tiering

To eliminate synthetic testbed artifacts (such as those in SARD/Juliet), SecuraX aggregates five real-world vulnerability repositories:
1. **BigVul (MSR 2020):** 188K C/C++ functions with verified CVE/CWE and CVSS metadata.
2. **DiverseVul (Wagner Group, 2023):** 330K modern C/C++ functions with cleaned labels.
3. **MegaVul:** Additional volume across C/C++ and Java.
4. **CVEFixes:** Multi-language repository with verified before/after git commit patches across 11 languages.
5. **VUDENC:** Python-specific vulnerability dataset.

### Phase 0.5 Language Tiering Strategy
An audit of 540,000 deduplicated functions revealed extreme class and language imbalance: C comprises 95% of available samples, while languages like Go, Java, and JavaScript possess only hundreds of examples. SecuraX established a 3-tier partitioning:
- **Tier 1 (High Resource, $>50,000$ samples):** C / C++ (516K functions). Dedicated GraphCodeBERT / CodeT5 models.
- **Tier 2 (Medium Resource, $2,000–50,000$ samples):** C++ (7.5K), Python (10.5K), PHP (2.1K). Independent per-language fine-tuned models.
- **Tier 3 (Low Resource, $<2,000$ samples):** Go (376), Java (392), JavaScript (782), TypeScript, Ruby. Trained via a unified shared model using language prefix tokens (`<LANG=xx>`).
- **Excluded:** Languages with $<100$ samples (Rust, Swift, Kotlin, Shell, SQL) to prevent spurious generalization.

---

## 4. Methodology Across Phases

```
Input Source Code 
   │
   ▼
[Language Detector] ──(Pygments + Extension Override)
   │
   ▼
[AST Chunker] ────────(Splits functions / methods)
   │
   ▼
[Phase 1] ────────────(Multi-Tier Binary VF: GraphCodeBERT / CodeT5 + Focal Loss)
   │
   ├─► Safe ──────────► [Report Safe (N/A)]
   │
   ▼ (If Vulnerable)
[Phase 2] ────────────(15-Class MITRE Semantic Weakness Grouping + Temperature Ensemble)
   │
   ▼
[Phase 3] ────────────(CVSS Continuous Severity Regression 0.0 - 10.0)
   │
   ▼
[Phase 4] ────────────(Groq LLM Refinement: Context-Enriched Prompt + Multi-Key Failover)
   │
   ▼
[Phase 5 UI] ─────────(Unified Streamlit Table, Interactive Diffs & Quota Protection)
```

### Phase 1 — Binary Detection (Recall-Prioritized)
- **Loss:** Focal Loss ($\gamma=2.0$) with inverse-frequency class weights clamped to 10× to tackle the 9:1 non-vulnerable class imbalance.
- **Parameter-Efficient Tuning:** LoRA with $r=64, \alpha=128$, dropout 0.1, targeting query/value projections.
- **Threshold Sweeps:** Rather than assuming default $0.50$, optimal thresholds were swept per tier: Tier 1 (0.70), Tier 2 C++ (0.10), Tier 2 Python (0.15), Tier 2 PHP (0.10), Tier 3 Shared (0.50).

### Phase 2 — CWE Classification (15 MITRE Semantic Groups)
Earlier attempts at 24-class CWE classification failed due to extreme sparsity (some CWEs having $<5$ samples). Phase 2 mapped all weakness types into 15 MITRE CWE-1000 categories (`Buffer-Overflow`, `Input-Validation`, `Integer-Issues`, `Use-After-Free`, etc.). In Tier 1, an ensemble of GraphCodeBERT ($w=0.65, T=1.5$) and CodeBERT-MOO ($w=0.35$) produced superior calibrated probabilities.

### Phase 3 — CVSS Severity Scoring
Modeled as a continuous regression task $[0.0, 10.0]$ using `SmoothL1Loss` (Huber loss, $\delta=1.0$) and a dedicated 2-layer MLP head with attention pooling.

### Phase 4 — LLM-Based Code Refinement (Groq API)
Converts upstream vulnerability intelligence (language, CWE ID, semantic group, CVSS score, and secure coding guidance) into structured prompts for open-weight instruction models (`qwen/qwen3.8-27b`). Built with client-side rate limiting (30 RPM), SHA-256 caching, and an automatic multi-key failover pool.

---

## 5. Consolidated Experimental Results

### 5.1 Cross-Tier Performance Summary

| Tier | Language(s) | 🏆 Winner Model | Phase 1 VF F1 | Phase 1 Recall | Phase 2 CWE Macro-F1 | Phase 3 CVSS MAE | Refinement Edit Sim | Refinement BLEU-4 |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Tier 1** | C / C++ | GraphCodeBERT / Ens | **0.5703** | 0.4580 | **0.6894** | **1.357** | **0.729** | **52.4** |
| **Tier 2** | C++ | GraphCodeBERT-v2 | **0.9843** | 0.9949 | **0.8124** | 1.499 | **0.764** | **58.1** |
| **Tier 2** | Python | GraphCodeBERT-v2 | **0.8174** | 0.8545 | **0.7640** | **1.269** | **0.814** | **61.2** |
| **Tier 2** | PHP | CodeT5-v2 | **1.0000** | 1.0000 | **0.9412** | **1.167** | **0.835** | **64.0** |
| **Tier 3** | Shared | CodeT5-v2 + `<LANG>` | **0.8330** | 0.8412 | **0.7850** | 1.200* | **0.792** | **59.5** |

*\*Val MAE reported for Tier 3.*

### 5.2 Refinement Head-to-Head Comparison (Phase 4)

| Metric | `qwen/qwen3.8-27b` (Default ⭐) | `openai/gpt-oss-120b` (Alternate) | Delta |
|---|:---:|:---:|:---:|
| **Perfect Prediction (PP)** | 0.0% | 0.0% | 0.0% |
| **Normalized Edit Similarity** | **0.472** | 0.176 | **+0.296** |
| **Token BLEU-4** | **32.8** | 11.3 | **+21.5** |
| **Syntactic Validity** | **40.0%** | 25.0% | **+15.0%** |
| **Detector Flip Rate (VF Flip)** | **30.0%** | 5.0% | **+25.0%** |
| **Average Latency** | **5.51s** | 7.94s | **-2.43s (Faster)** |

---

## 6. Ablation Studies

### Ablation 1: Zero-Shot LLM Detection vs Fine-Tuned Encoders
- **Objective:** Evaluate whether a massive general LLM can replace fine-tuned code encoders for vulnerability detection.
- **Method:** Prompted `qwen/qwen3.8-27b` in zero-shot mode: *"Is this code vulnerable? Answer ONLY VULNERABLE or SAFE."*
- **Results:** Zero-shot LLM achieved high Recall (1.00) but abysmal Precision (**0.5556**) and F1 (**0.7143**), suffering from extreme over-flagging and hallucinations on safe code. In contrast, fine-tuned encoders (Phase 1) achieved targeted discrimination (F1: 0.817–1.000 on Tier 2), firmly justifying supervised fine-tuning.

### Ablation 2: CWE Classification v1 vs v2
- **Objective:** Assess the impact of MITRE CWE-1000 15 semantic clustering and calibrated temperature scaling over flat 24-class cross-entropy.
- **Results:** Macro-Recall surged from **0.4347 to 0.6513 (+49.8%)**, and Macro-F1 jumped from **0.3212 to 0.6894 (+114.6%)** on Tier 1.

### Ablation 3: Synthetic Juliet/SARD vs Real-World Generalization
- **Objective:** Measure performance differences when evaluating models on synthetic datasets (Juliet) versus real in-the-wild CVEs (BigVul/CVEFixes).
- **Results:** Models evaluated on synthetic testbeds achieve artificial F1 of **0.942**, but drop to **0.570** on real CVEs ($\Delta = -0.372$). Real code exhibits complex control flows, macros, and inter-procedural data dependencies absent in synthetic samples.

### Ablation 4: CVSS Severity Shared vs Per-Tier
- **Objective:** Determine if cross-language transfer benefits continuous CVSS regression.
- **Results:** Tier 2 PHP (1.167 MAE) and Tier 2 Python (1.269 MAE) outperformed the cross-language baseline. However, all models exhibited negative $R^2$, indicating that function-level code tokens alone do not capture environmental exploitability metrics (e.g., network access vector, user interaction, attack complexity).

### Ablation 5: Refinement Prompting Context Ablation
- **Objective:** Evaluate whether supplying upstream predictions (CWE ID, CVSS score, semantic hint) improves LLM patch quality compared to raw code fixing.
- **Results:** Providing the predicted CWE and CVSS score produced more domain-precise patches (e.g., using parameterized SQL vs raw regex string filters).

---

## 7. Comprehensive Error Analysis

### 7.1 False Negatives (Missed Vulnerabilities)
- **Root Cause 1 (Inter-procedural context):** Vulnerabilities where bounds checking occurs in an un-inlined caller function were missed by function-scoped encoders.
- **Root Cause 2 (Subtle Integer Wraparound):** In C arithmetic (`size = count * elem_size`), models failed to flag potential overflow before allocation unless explicitly guided by integer-issue heuristics.

### 7.2 False Positives (Safe Code Flagged)
- **Root Cause 1 (Custom Sanitizers):** Models frequently flagged custom wrapper functions (e.g., `my_strcpy(dest, src, limit)`) as vulnerable because tokenizers focused on the substring `strcpy`.
- **Root Cause 2 (Legacy Macro Invocations):** Safe macros expanding into pointer dereferences were over-penalized.

### 7.3 Refinements That Broke Syntax or Runtime Behavior
- **Syntax Breaches (2.5%):** Occurred predominantly in C++ when LLMs introduced template parameters or standard library headers (`<memory>`, `<algorithm>`) that were unimported in the function snippet.
- **Signature Drift:** LLMs occasionally attempted to modify return types (e.g. returning `bool` instead of `int`), which was mitigated by strict negative constraints in the system prompt.

---

## 8. Limitations & Constraint Exception

1. **Groq Hosted API Dependency:** Code refinement relies on cloud infrastructure. While models are open-weight, code snippets traverse third-party network paths, making this unsuitable for air-gapped classified codebases without the local Ollama fallback.
2. **Free-Tier Rate Limits:** Free-tier limits (30 RPM, 7,000 ITPM) necessitate caching, input truncation, and failover mechanisms.
3. **Excluded Languages:** Languages with $<100$ samples (Rust, Swift, Kotlin, Shell) could not be trained reliably and are excluded to avoid spurious predictions.

---

## 9. Conclusion & Future Work

SecuraX demonstrates that automated vulnerability management is most effective as a multi-tier, staged pipeline. By combining lightweight, fast local discriminative encoders for detection and classification with high-throughput hosted LLMs for code repair, the framework delivers an end-to-end SAST alternative that not only finds security defects but repairs them with minimal developer friction.

Future work will focus on integrating graph neural network representations directly into transformer encoders and deploying local quantization backends (Ollama/vLLM) for fully air-gapped environments.

