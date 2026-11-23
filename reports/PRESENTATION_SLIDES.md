# SecuraX: Presentation Slide Deck (10-Minute Technical Defense)

**Topic:** Automated Source Code Vulnerability Detection, Classification, Severity Scoring & LLM-Assisted Refinement  
**Author:** Preet Makadiya (B.Tech Minor Project)  
**Project Guide:** [GUIDE_NAME], [INSTITUTE_NAME]  
**Audience:** Technical Mentors, Evaluators, and Security Researchers  

---

## Slide 1: Title & Project Overview
- **Title:** SecuraX — AI-Powered Multi-Tier Vulnerability Intelligence & Code Repair
- **Problem Statement:** Static code analysis tools (SAST) produce 50–70% false alarms, lack automated fix generation, and treat vulnerability analysis in isolation.
- **Core Contribution:** An end-to-end multi-tier pipeline connecting **Detection $\rightarrow$ CWE Taxonomy $\rightarrow$ CVSS Severity $\rightarrow$ LLM Code Repair $\rightarrow$ Interactive UI**.
- **Constraint:** 100% Free / Open-Source foundation (PyTorch, PEFT, Hugging Face), with a documented Groq API exception for rapid repair inference.

---

## Slide 2: The Data Challenge & Phase 0.5 Language Tiering
- **Corpus:** 540,000 deduplicated functions from BigVul, DiverseVul, MegaVul, and CVEFixes across 11 languages.
- **The Imbalance Reality:**
  - C represents 95% of real-world CVE data.
  - Languages like Go, Java, JavaScript, and Ruby have only hundreds of fix pairs.
- **The SecuraX Multi-Tier Strategy:**
  - **Tier 1 (C / C++):** >50K samples $\rightarrow$ Dedicated GraphCodeBERT & CodeT5 models.
  - **Tier 2 (C++, Python, PHP):** 2K–50K samples $\rightarrow$ Independent per-language fine-tuned models.
  - **Tier 3 (Shared: Go, Java, JS, TS, Ruby):** <2K samples $\rightarrow$ Unified model using `<LANG=xx>` tokens.
  - **Excluded:** Languages with <100 samples (Rust, Swift, Kotlin) to avoid spurious routing.

---

## Slide 3: Phase 1 — Binary Vulnerability Detection (Recall Focus)
- **Objective:** Maximize Recall without destroying Precision (9:1 non-vulnerable imbalance).
- **Architecture:** GraphCodeBERT + Attention Pooling + LoRA ($r=64, \alpha=128$) + Focal Loss ($\gamma=2.0$).
- **Per-Tier Threshold Calibration:**
  - Tier 1 (C/C++): Threshold = 0.70 (F1 = 0.5703, Recall = 0.4580)
  - Tier 2 (C++): Threshold = 0.10 (F1 = 0.9843, Recall = 0.9949)
  - Tier 2 (PHP): Threshold = 0.10 (F1 = 1.0000, Recall = 1.0000)
  - Tier 2 (Python): Threshold = 0.15 (F1 = 0.8174, Recall = 0.8545)
  - Tier 3 (Shared): Threshold = 0.50 (F1 = 0.8330, Recall = 0.8412)
- **Ablation 1 Finding:** Supervised fine-tuning significantly outperforms zero-shot LLMs (which had 44% false alarm rates).

---

## Slide 4: Phase 2 — Multi-Class CWE Classification
- **The v1 Dilemma:** 24-class flat categorization failed due to extreme class sparsity.
- **The v2 Solution:** 15 MITRE CWE-1000 Semantic Weakness Clusters (`Buffer-Overflow`, `Input-Validation`, `Use-After-Free`, `Integer-Issues`, etc.).
- **Tier 1 Ensemble Calibration:**
  - GraphCodeBERT-v2 ($w=0.65$) + CodeBERT-MOO ($w=0.35$) with Temperature Scaling ($T=1.5$).
  - **Results:** Macro-Recall **+49.8%** (0.6513), Macro-F1 **+114.6%** (0.6894).

---

## Slide 5: Phase 3 — CVSS Severity Scoring (Continuous Regression)
- **Objective:** Predict CVSS impact score ($0.0$ to $10.0$) for risk-based developer triage.
- **Architecture:** CodeT5 / GraphCodeBERT with SmoothL1Loss (Huber $\delta=1.0$) and MLP attention head.
- **Key Results:**
  - Best model: Tier 2 PHP CodeT5 (MAE = 1.167), Tier 2 Python GraphCodeBERT (MAE = 1.269).
  - CVSS Band Accuracy (Low/Med/High/Critical): **68–74%**.
- **Crucial Finding:** Severity is bounded by mean regression around ~5.38. Function tokens alone cannot capture environmental access vectors or user interaction metrics.

---

## Slide 6: Phase 4 — LLM-Based Code Refinement via Groq
- **Why Groq?** Local CodeT5 fine-tuning on generation discards LLM instruction capabilities; local 70B models exceed free hardware. Groq LPU API serves open-weight models (`qwen/qwen3.8-27b`) with sub-second latency.
- **Head-to-Head Comparison:**
  - `qwen/qwen3.8-27b` (Winner) vs `openai/gpt-oss-120b`:
  - Normalized Edit Similarity: **0.472 vs 0.176** (+0.296)
  - Token BLEU-4: **32.8 vs 11.3** (+21.5)
  - Detector Flip Rate: **30.0% vs 5.0%**
- **Resilience Engineering:** 30 RPM rate limiter, persistent SHA-256 caching, multi-key failover pool.

---

## Slide 7: Phase 5 — System Integration & Streamlit Dashboard
- **Standard Output Schema:**
  `PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score`
- **Key Pipeline Features:**
  - Pygments `guess_lexer()` + extension override for strict tier isolation.
  - AST function chunker for Python, C/C++, PHP, JS, Go.
  - Refinement Quota Cap (default 20) with on-demand per-snippet repair buttons.
  - Interactive unified diff view with side-by-side syntax highlighting.
  - Single-command launch: `streamlit run app/main.py`.

---

## Slide 8: Key Ablations & Discoveries
1. **Zero-Shot LLM vs Fine-Tuning (Ablation 1):** Proves fine-tuned models are essential for high-precision detection (LLMs hallucinate on safe code).
2. **Taxonomy Reform (Ablation 2):** Semantic clustering delivers +114.6% Macro-F1.
3. **Juliet vs Real CVEs (Ablation 3):** Performance gap of -0.372 proves synthetic testbeds create false confidence.
4. **Refinement Context (Ablation 5):** Feeding upstream CWE and CVSS features into the prompt ensures minimal, targeted patches.

---

## Slide 9: Error Analysis & Limitations
- **False Negatives:** Inter-procedural bounds checking outside function boundaries.
- **False Positives:** Custom sanitizer functions containing keywords like `strcpy`.
- **Constraint Exception:** Third-party data transit on Groq free-tier; mitigated by offline local fallback option (Ollama).

---

## Slide 10: Conclusion & Demo Transition
- **Summary:** SecuraX bridges the gap from detection to verified code repair across 8+ languages.
- **Demo Showcase:** Live walkthrough on C (Buffer Overflow), Python (SQLi), and PHP (XSS).

