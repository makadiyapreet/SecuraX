# SecuraX: Limitations & Threats to Validity

**Author:** Preet Makadiya (B.Tech Minor Project)  
**Guide / Advisor:** [GUIDE_NAME], [INSTITUTE_NAME]  
**Document:** `docs/audit/LIMITATIONS_AND_VALIDITY.md`  

---

## 1. Internal Validity

- **Data Sourcing and Class Imbalance:**  
  Historical vulnerability datasets (e.g. BigVul, DiverseVul, MegaVul, CVEFixes) frequently exhibit duplicate commits, synthetic labeling artifacts, and extreme class imbalances. In particular, our data audit revealed that `tier2_php` and `tier3_shared` test splits consisted exclusively of positive vulnerable samples (`vul = 1`), rendering precision metrics trivial and AUROC undefined ($NaN$).
- **Multi-Dataset Deduplication:**  
  While cross-split deduplication was performed, public datasets often contain functions with cosmetic variations (variable renaming, minor whitespace adjustments) that can artificially boost test set performance.

---

## 2. External Validity (Real-World Generalization)

- **Inter-procedural Context Blindness:**  
  Transformer encoders operate on local function chunks (up to 512 tokens). Real-world vulnerabilities often depend on global application state, remote configuration flags, or complex inter-procedural data flows that are invisible to local function analysis.
- **Novel and Zero-Day CWEs:**  
  The 15 MITRE semantic classes encompass common security weaknesses, but novel architecture flaws, cryptographic protocol design errors, and application-specific business logic bypasses cannot be identified without dedicated domain-specific specifications.

---

## 3. Construct Validity

- **Proxy Evaluation Metrics:**  
  BLEU and CodeBLEU scores measure textual and AST syntactic resemblance to human patches, not functional security or exploit neutralization. A generated patch may achieve high BLEU while leaving the underlying vulnerability unpatched.
- **Phase 7 Self-Verification Scope:**  
  The closed-loop self-verification verifies syntax and known anti-patterns, but does not execute comprehensive unit test suites or symbolic execution proofs.

---

## 4. Neuro-Symbolic Boundaries

- **Static Rule Fallibility:**  
  The deterministic override layer inspects code for defensive controls (parameterized queries, sanitizers, bounds checks). While this dramatically reduces neural false positives on idiomatic defensive code, sophisticated adversarial bypasses (e.g., partial escapes, second-order injections) may deceive shallow static patterns. Hence, outputs are explicitly marked as `"Controls detected - likely safe"` rather than guaranteed benign.

---

## 5. Third-Party Infrastructure

- **Groq Hosted LPU Inference:**  
  Phase 4 code refinement utilizes open-weight models (`qwen/qwen3.8-27b`) served over Groq's free-tier hosted LPU infrastructure. Rate limits, cloud availability, and model version deprecations represent external dependencies managed through dual-key automatic rotation and local disk caching.

