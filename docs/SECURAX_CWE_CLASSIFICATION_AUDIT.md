# SecuraX — CWE Classification & Taxonomy Audit
## In-Depth Analysis of 15-Class Semantic Grouping, MITRE Hierarchy, Class-Index Mappings & Inference Calibration

### 1. Executive Summary & Core Architectural Principle

SecuraX incorporates a **15-Class MITRE CWE Semantic Grouping** designed in Phase 2 to map the vast, sparse space of over 800+ known MITRE Common Weakness Enumerations into 15 semantically coherent categories derived from the **MITRE CWE-1000 Research View**.

A fundamental finding of this audit is:
> **The neural model classifies input code into 15 coarse semantic groups, NOT directly into fine-grained individual CWEs.**
> When individual fine-grained CWE IDs (such as CWE-601, CWE-89, CWE-78) are presented to users or dashboards, they must be resolved deterministically using authoritative syntactic and semantic evidence or clearly labeled as representative group archetypes.

Under no circumstances should the system fabricate a fine-grained CWE ID when neither the neural logits nor the code evidence decisively substantiate it. When uncertainty exists, SecuraX must transparently output:
```text
CWE Classification: Uncertain (Review Recommended)
```

---

### 2. Complete Taxonomy Mapping

The 15 semantic groups and their canonical representative CWEs:

| Class Index | Semantic Group | Primary Representative | CWE Description | Typical MITRE Members |
|---|---|---|---|---|
| **0** | `Buffer-Overflow` | `CWE-119` | Classic / Unbounded Buffer Overflow | CWE-119, CWE-120, CWE-129 |
| **1** | `OOB-Read` | `CWE-125` | Out-of-Bounds Memory Read | CWE-125 |
| **2** | `OOB-Write` | `CWE-787` | Out-of-Bounds Memory Write | CWE-787 |
| **3** | `Use-After-Free` | `CWE-416` | Pointer Dereference After Free | CWE-416, CWE-824 |
| **4** | `Double-Free` | `CWE-415` | Releasing Already-Freed Pointer | CWE-415, CWE-763 |
| **5** | `NULL-Deref` | `CWE-476` | NULL Pointer Dereference | CWE-476, CWE-252 |
| **6** | `Integer-Issues` | `CWE-190` | Integer Overflow or Wraparound | CWE-190, CWE-191, CWE-189, CWE-369, CWE-682, CWE-704 |
| **7** | `Input-Validation` | `CWE-20` | Injection & Input Validation | CWE-20, CWE-74, CWE-77, CWE-78, CWE-79, CWE-89, CWE-94, CWE-134, CWE-611, CWE-918 |
| **8** | `Info-Exposure` | `CWE-200` | Sensitive Information Leakage | CWE-200, CWE-209, CWE-532 |
| **9** | `Access-Control` | `CWE-284` | Authorization & Authentication | CWE-284, CWE-264, CWE-269, CWE-281, CWE-285, CWE-287, CWE-732, CWE-862 |
| **10** | `Crypto-Issues` | `CWE-327` | Cryptographic Flaws / Broken Ciphers | CWE-327, CWE-310, CWE-311, CWE-320, CWE-330, CWE-345, CWE-346, CWE-347, CWE-354 |
| **11** | `Resource-Mgmt` | `CWE-400` | Resource Consumption / Exhaustion | CWE-400, CWE-399, CWE-404, CWE-770, CWE-772, CWE-834, CWE-835, CWE-674 |
| **12** | `Race-Condition` | `CWE-362` | Concurrent Synchronization Flaw | CWE-362 |
| **13** | `Path-Traversal` | `CWE-22` | Path Traversal / Open Redirect | CWE-22, CWE-59, CWE-426, CWE-601 |
| **14** | `Other-Security` | `CWE-693` | Defensive Failures & Deserialization | CWE-693, CWE-502, CWE-798, CWE-494, CWE-522, CWE-617, CWE-664, CWE-665, CWE-668, CWE-754 |

---

### 3. Root Causes of Observed Misclassifications

#### Failure 1: JavaScript Open Redirect returned CWE-400
- **Root Cause:** In `dataset_cwe.py`, `CWE-601` was correctly categorized under Group 13 `Path-Traversal`. However, in `cwe_taxonomy.py`:
  1. `CWE_METADATA` omitted `CWE-601` entirely.
  2. `CODE_SIGNATURES` lacked regex rules for `res.redirect(`, `window.location`, and HTTP `Location:` headers.
  3. When the Tier 1 C/C++ neural model evaluated JavaScript code, it produced out-of-distribution diffuse logits where Index 11 (`Resource-Mgmt` / `CWE-400`) marginally won argmax.
- **Resolution:** Added `CWE-601` (Open Redirect) to `CWE_METADATA`, added comprehensive redirect patterns to `CODE_SIGNATURES`, and implemented calibrated cross-tier handling that prioritizes concrete syntactic evidence over cross-tier neural noise.

#### Failure 2: Python Path Traversal returned CWE-400
- **Root Cause:** The regex pattern for `CWE-22` was restricted to `os.path.join.*user`. A realistic function named `download_file(filename)` using `os.path.join(base_dir, filename)` did not match the pattern. Without an evidence match, the model fell back to out-of-distribution neural logits where `Resource-Mgmt` won argmax.
- **Resolution:** Broadened `CWE-22` regex to cover `os.path.join`, `path.join`, `filepath.Join`, and file opens with path parameters, correctly mapping `download_file()` to `CWE-22 (Path Traversal)`.

#### Failure 3: C Integer Overflow returned CWE-362
- **Root Cause:** The arithmetic signature required exact variable names. Furthermore, `CWE-362` contained overly broad tokens (`flock`, `race`) that caused false concurrency attributions.
- **Resolution:** Extended `CWE-190` signature to match arithmetic operations on integers/size variables preceding dynamic allocation, and tightened `CWE-362` to explicit concurrency constructs (`pthread_create`, `synchronized`, `sem_wait`).

---

### 4. Authoritative Decoding Pipeline

The unified mapping follows a single path across all SecuraX modules:
```
Raw Snippet
    │
    ▼
Independent Security Validation & Syntax Verification
    │
    ▼
Neural Softmax Logits (15-Class Probability Vector)
    │
    ├── Check Entropy: H > 0.65 indicates cross-tier / diffuse distribution
    │
    ├── Apply Language Filtering: Suppress memory corruption classes (0-4)
    │   on managed runtimes (Python, JS, PHP, Java, Go) unless FFI detected
    │
    ▼
Evidence-Based Disambiguation (CODE_SIGNATURES)
    │
    ├── Evidence Matches Neural Group ──► Status: "corroborated" (Confidence >= 88%)
    ├── Cross-Tier or Low Confidence ──► Evidence takes precedence
    ├── High Confidence In-Domain ──► Neural Group validated
    └── Diffuse Noise & No Evidence ──► Status: "uncertain" -> Display: Uncertain (Review Recommended)
```

### 5. Verification Confirmation
- Existing model weights modified: **NO**
- Model retraining executed: **NO**
- Single source of truth maintained in: [`src/data/cwe_taxonomy.py`](src/data/cwe_taxonomy.py)

