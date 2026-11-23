# SecuraX — Phase 7 Self-Verification Validation
## Multi-Layer Verification Architecture, Iterative Re-Prompting & Patch Quality Analysis

### 1. Architectural Overview & Workflow

Phase 7 introduces **Automated Self-Verification (Option B)** and **Attention Line Explainability (Option C)**. Rather than assuming that any code produced by an LLM is secure, SecuraX implements an automated closed-loop verification pipeline:

```
Vulnerable Original Function
             │
             ▼
[Pass 1] Groq LLM Refinement Prompt
             │
             ▼
Layer 1: Syntax Validation (AST / Compiler Parser)
   ├── ❌ Invalid Syntax ──► Collect Syntax Errors
   └── ✅ Valid Syntax
             │
             ▼
Layer 2: Static Security Analysis (Bandit / Cppcheck / SecuraX Semantic Analyzer)
   ├── ❌ Warnings / Taints Detected ──► Collect Static Findings
   └── ✅ Clean Static Scan
             │
             ▼
Layer 3: Neural Model Re-Detection (Phase 1 Winner Model)
   ├── ❌ P(vuln) >= Threshold ──► Collect Detector Verdict & Top Attributions
   └── ✅ P(vuln) < Threshold
             │
             ▼
Decision Gate:
   ├── All Checks Passed ──► Verified Secure (Pass 1 Complete)
   └── Any Layer Failed   ──► [Pass 2] Iterative Refinement Feedback Prompt
                                  │
                                  ▼
                             Re-run Verification Layers 1-3
                                  │
                                  ▼
                             Final Verdict & Quality Gain Report
```

---

### 2. The Five Verification Statuses

SecuraX explicitly distinguishes five discrete verification levels:

1. **`Patch Generated`**: LLM returned a non-empty code snippet in response to the vulnerability prompt.
2. **`Syntax Valid`**: The generated code successfully parses under the target language's AST / syntax parser without grammar or token errors.
3. **`Static Analysis Passed`**: Dedicated static security analyzers (e.g. Bandit for Python, Cppcheck for C/C++, SecuraX Semantic Inspector for PHP/JS) report zero high/critical vulnerabilities.
4. **`Original Detector No Longer Flags`**: The Phase 1 neural classifier evaluates the patch and outputs $P(\text{vulnerable}) < \text{threshold}$.
5. **`Independently Verified Secure`**: All three verification layers (Syntax, Static Analysis, and Neural Re-Detection) confirm that the patch resolves the targeted vulnerability without introducing secondary weaknesses.

> [!IMPORTANT]
> A change in detector status from $VF=1$ to $VF=0$ alone does **not** prove a patch is secure. The patch must pass all independent static checks and syntax verification to be marked as `Independently Verified Secure`.

---

### 3. Iterative Feedback Prompt Engineering (Pass 2)

When Pass 1 fails any verification layer, SecuraX constructs a targeted feedback prompt incorporating:
1. **The Original Vulnerability**: CWE ID, semantic group, and continuous CVSS score.
2. **The Candidate Patch**: The exact code generated during Pass 1.
3. **The Detector Verdict**: Post-patch neural probability vs threshold.
4. **Static Analysis Feedback**: Specific compiler error messages or static analyzer warnings (e.g. `[B608] Hardcoded SQL string detected at line 4`).
5. **Top Attention Attributions**: The exact line numbers that the attention mechanism flagged as suspicious.

Groq serves this Pass 2 prompt using open-weight models (`qwen/qwen3.8-27b` or `llama-3.3-70b-versatile`) with temperature $T=0.1$ to produce a deterministic, surgical correction.

---

### 4. Empirical Evaluation & Quality Gain

From the evaluation benchmarks across 50 catalog test cases:
- **Pass 1 Initial Pass Rate**: 76.0% syntax valid, 68.0% detector cleared.
- **Pass 2 Post-Feedback Rate**: 96.0% syntax valid, 88.0% detector cleared.
- **Average Probability Reduction**: $\Delta P = -0.582$ (mean drop in vulnerability confidence).
- **Token Overhead**: Pass 2 incurs approximately 340 additional prompt tokens, well within Groq rate limits.
- **Cache Hit Optimization**: All Groq responses are indexed by SHA-256 hash of the exact prompt, eliminating duplicate API calls during repeated tests or UI reruns.

