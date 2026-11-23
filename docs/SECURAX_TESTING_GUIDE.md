# SecuraX Comprehensive Testing Guide & Verification Manual

This document provides complete instructions for executing, evaluating, and extending the automated test suites of **SecuraX**.

---

## 1. Quick Start: Running Tests

The test suite is organized into two execution modes:

### Mode A: Lightweight Regression Suite (Recommended for Rapid Testing)
Evaluates all 50 ground-truth fixtures across language detection, chunking, static security analysis, and calibrated CWE resolution without loading heavy PyTorch model weights. Runs in **~3 seconds**.

```bash
# Run 50-fixture benchmark and generate results/SECURAX_REGRESSION_TEST_RESULTS.json
python3 tests/run_all_tests.py --mode lightweight
```

### Mode B: Full Integration Suite
Evaluates all unit, pipeline integration, and neural inference components using local PyTorch models on MPS/CPU/CUDA.

```bash
# Run all unit and regression tests via pytest (38 tests)
python3 -m pytest tests/ -v -k "not integration"

# Run end-to-end integration tests (includes neural inference)
python3 -m pytest tests/ -v
```

---

## 2. Test Catalog Breakdown (50 Fixtures Across 9 Languages)

The test catalog in [`tests/fixtures/catalog.py`](tests/fixtures/catalog.py) contains **50 curated, authoritative test cases**:
- **25 Vulnerable Fixtures (`TC-V01` through `TC-V25`)**
- **25 Safe Baseline Fixtures (`TC-S01` through `TC-S25`)**

### Language Distribution:
- **C:** Buffer overflow, memory management, integer overflow, race conditions (`TC-V06`, `TC-V07`, `TC-V20`, `TC-V21`, `TC-V25`, etc.)
- **C++:** Out-of-bounds indexing, buffer overflow (`TC-V08`, `TC-S08`)
- **Python:** SQL injection, command injection, path traversal, deserialization, weak crypto, hardcoded secrets, info exposure (`TC-V01`, `TC-V02`, `TC-V09`, `TC-V12`, `TC-V14`, `TC-V16`, `TC-V17`, `TC-V19`, `TC-V22`, `TC-V23`, `TC-V24`)
- **PHP:** SQL injection, reflected XSS, command injection (`TC-V03`, `TC-V04`, `TC-V11`, `TC-S03`, `TC-S04`, `TC-S11`)
- **JavaScript:** DOM XSS, shell command injection (`TC-V05`, `TC-V10`, `TC-S05`, `TC-S10`)
- **TypeScript:** Hardcoded secrets (`TC-V13`, `TC-S13`)
- **Go:** Path traversal (`TC-V15`, `TC-S15`)
- **Java:** Weak cryptographic hashing (`TC-V18`, `TC-S18`)
- **Ruby:** File handling and command execution baselines

---

## 3. Test Modules & Scope

| Test File | Target Module | Scope |
|:---|:---|:---|
| [`tests/test_language_detection.py`](tests/test_language_detection.py) | `src/pipeline/language_detector.py` | Pygments lexer guessing, extension overrides, tier mapping, unsupported language handling. |
| [`tests/test_function_extraction.py`](tests/test_function_extraction.py) | `src/pipeline/chunker.py` | Python AST parser, C/C++/Java/Go brace parser, JS/TS arrow functions, LOC calculation, fallback chunks. |
| [`tests/test_cwe_mapping.py`](tests/test_cwe_mapping.py) | `src/data/cwe_taxonomy.py` | 15-class semantic taxonomy integrity, SQLi disambiguation to CWE-89, low-confidence uncertainty handling. |
| [`tests/test_binary_detection.py`](tests/test_binary_detection.py) | `src/pipeline/model_manager.py` | Per-tier threshold checks, model manager initialization, heuristic fallback, neural inference. |
| [`tests/test_severity.py`](tests/test_severity.py) | `src/pipeline/model_manager.py` | Continuous CVSS score calculation (0.0–10.0), severity band mapping, neural regression. |
| [`tests/test_refinement.py`](tests/test_refinement.py) | `src/refinement/` | Prompt template formatting, JSON response parser, multi-language syntax validator. |
| [`tests/test_self_verification.py`](tests/test_self_verification.py) | `src/refinement/self_verification.py` | Empty patch rejection, syntax error rejection, static analysis issue rejection, diagnostic feedback prompt. |
| [`tests/test_explainability.py`](tests/test_explainability.py) | `src/pipeline/explainability.py` | Token attention weight pooling, line-level normalization, HTML heatmap generation. |
| [`tests/test_reporting.py`](tests/test_reporting.py) | `src/pipeline/securax_pipeline.py` | Strict 7-column CSV schema consistency, JSON detail serialization, safe code N/A verification. |
| [`tests/test_phase5_pipeline.py`](tests/test_phase5_pipeline.py) | `src/pipeline/securax_pipeline.py` | Multi-language end-to-end execution, refinement cap enforcement, API key rotation fallback. |

### Dedicated Audit Test Suites

| Suite | File | Scope & Target Behaviors | Pass Rate |
|:---|:---|:---|:---|
| **Five Observed Cases** | [`tests/regression/test_five_observed_cases.py`](tests/regression/test_five_observed_cases.py) | Validates all 5 mandatory audit cases: JS Open Redirect (CWE-601), Python Path Traversal (CWE-22), C Integer Overflow (CWE-190), PHP Secure Upload (Safe hard-negative), and Java Deserialization (`readPayload()` extraction). | **5/5 PASSED (100%)** |
| **Hard-Negative Suite** | [`tests/hard_negatives/test_hard_negatives.py`](tests/hard_negatives/test_hard_negatives.py) | Validates 9 security controls where defensive patterns must evaluate as `Safe` / `CWE: N/A` without false-positive alarms: parameterized SQL (Python, PHP), safe DOM manipulation (`textContent`), output escaping (`htmlspecialchars`), safe subprocess arrays, path sanitization (`os.path.basename`), bounded integer checks (`SIZE_MAX / width`), and bounded copy primitives (`strncpy`). | **9/9 PASSED (100%)** |
| **End-to-End Integration** | [`tests/integration/test_end_to_end_pipeline.py`](tests/integration/test_end_to_end_pipeline.py) | Validates full pipeline flow across all 9 languages, tier dispatching, unsupported language rejections, strict 7-column table schema compliance, and `N/A` semantics for safe code. | **4/4 PASSED (100%)** |

```bash
# Run all dedicated audit test suites together (18 tests total):
python3 -m pytest tests/regression/ tests/hard_negatives/ tests/integration/ -v
```

---

## 4. Verification Assertions & Pass Criteria

1. **Vulnerability Detection (VF):**
   - For all `TC-V01` through `TC-V25`, `is_vulnerable == True`.
   - For all `TC-S01` through `TC-S25`, `is_vulnerable == False`.
2. **CWE Classification:**
   - Vulnerable snippets must resolve to their target CWE (e.g. `CWE-89` for SQLi) or their target semantic group (`Input-Validation`).
   - Predictions with $<25\%$ neural confidence and no code signatures must return `Uncertain (Review Recommended)`.
   - Safe snippets must strictly return `N/A`.
3. **Severity Scoring:**
   - Continuous score between $0.0$ and $10.0$.
   - Band mapping: `Low` (<4.0), `Medium` (4.0–6.9), `High` (7.0–8.9), `Critical` ($\ge$9.0).
   - Safe snippets must strictly return `N/A`.
4. **Table Output Schema:**
   - Output rows must contain exactly:
     `PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score`

---

## 5. Troubleshooting & FAQ

### Q: Why do I see a warning about PEFT config parameters?
```
UserWarning: Unexpected keyword arguments ['kasa_config', 'monteclora_config', 'velora_config'] for class LoraConfig
```
*Explanation:* The saved checkpoints were trained with a slightly newer version of PEFT that serialized forward-looking parameters. PEFT automatically ignores them during inference, so this warning is harmless.

### Q: How do I test without consuming Groq API quota?
Run tests with `python3 tests/run_all_tests.py --mode lightweight`. The lightweight suite does not invoke Groq API calls; all LLM prompts and responses are validated via unit tests and cached responses in `tests/test_refinement.py`.

### Q: What should I do if a model loading takes 15–20 seconds?
On Apple Silicon (MPS) or CPU, loading PyTorch weights into memory has an initial disk read cost. `LocalModelManager` caches models in memory as singletons. Subsequent calls on the same tier take **<100ms**.

