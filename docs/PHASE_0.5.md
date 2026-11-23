# SecuraX — Phase 0.5: Multi-Language Data Audit & Tiering Results

    ⁠*Date:* 2026-09-25
    ⁠*Status:* ✅ COMPLETE
    ⁠*Script:* ⁠ src/data/audit_multilang.py ⁠
    ⁠*Output:* ⁠ data/processed/manifest.json ⁠ + split CSVs

---

## Executive Summary

Phase 0.5 successfully loaded, normalized, deduplicated, and tiered vulnerability data from _5 datasets_ across _27 programming languages, yielding \*\*540,488 unique samples_ ready for model training.

| Metric                              | Value               |
| ----------------------------------- | ------------------- |
| _Total raw rows loaded_             | 1,248,124           |
| _After removing empty code_         | 1,245,231           |
| _After cross-dataset deduplication_ | _540,488_           |
| _Duplicates removed_                | 704,743 (56.6%)     |
| _Languages with data_               | 27                  |
| _Languages in training tiers_       | 11 (Tier 1 + 2 + 3) |
| _Unique CWE classes_                | 181+                |
| _Samples with CVSS scores_          | 6,094               |
| _Samples with fix pairs_            | 198,816             |

---

## 1. Dataset Loading Summary

All 5 target datasets were loaded successfully:

| #   | Dataset      | Source                                 | Raw Rows | Languages    | Notes                                                        |
| --- | ------------ | -------------------------------------- | -------- | ------------ | ------------------------------------------------------------ |
| 1   | _BigVul_     | HuggingFace (⁠ bstee615/bigvul ⁠)      | 217,007  | C, C++       | Local CSV lacked code columns; fell back to HF               |
| 2   | _CVEFixes_   | HuggingFace (⁠ hitoshura25/cvefixes ⁠) | 12,987   | 10 languages | Multi-language with vulnerable/fixed code pairs              |
| 3   | _MegaVul_    | HuggingFace (⁠ hitoshura25/megavul ⁠)  | 671,797  | C, C++       | Largest single dataset; extensive fix pairs                  |
| 4   | _DiverseVul_ | HuggingFace (⁠ benjis/diversevul ⁠)    | 330,492  | C            | Includes both vulnerable (18,945) and non-vulnerable samples |
| 5   | _VUDENC_     | HuggingFace (⁠ DetectVul/Vudenc ⁠)     | 15,841   | Python       | Line-level format; converted to function-level               |

### Data Pipeline

Raw Loading → Schema Normalization → Empty Code Removal → Cross-Dataset Deduplication
1,248,124 → 1,248,124 → 1,245,231 → 540,488

---

## 2. Per-Language Statistics

### Primary Languages (In Training Tiers)

| Language     |   Total | Vulnerable | Non-Vuln |     CWE |  CVSS | Fix Pairs | #CWEs | Tier | Sources                                                                   |
| ------------ | ------: | ---------: | -------: | ------: | ----: | --------: | ----: | :--: | ------------------------------------------------------------------------- |
| _C_          | 516,562 |     50,873 |  465,689 | 436,039 | 2,233 |   186,037 |   181 | _1_  | DiverseVul: 330,491 · BigVul: 163,210 · MegaVul: 20,163 · CVEFixes: 2,698 |
| _Python_     |  10,483 |        957 |    9,526 |  10,334 |   332 |       753 |   120 | _2_  | VUDENC: 9,724 · CVEFixes: 759                                             |
| _C++_        |   7,548 |      5,288 |    2,260 |   7,316 |   344 |     7,545 |   115 | _2_  | MegaVul: 4,725 · BigVul: 2,357 · CVEFixes: 466                            |
| _PHP_        |   2,100 |      2,100 |        0 |   1,900 | 1,226 |     2,089 |   112 | _2_  | CVEFixes: 2,100                                                           |
| _Other_      |     982 |        982 |        0 |     870 |   650 |       978 |   111 |  3   | CVEFixes: 982                                                             |
| _JavaScript_ |     782 |        782 |        0 |     670 |   440 |       776 |    91 |  3   | CVEFixes: 782                                                             |
| _Java_       |     392 |        392 |        0 |     343 |   190 |       389 |    78 |  3   | CVEFixes: 392                                                             |
| _Go_         |     376 |        376 |        0 |     298 |   132 |       372 |    85 |  3   | CVEFixes: 376                                                             |
| _Ruby_       |     341 |        341 |        0 |     279 |   200 |       339 |    64 |  3   | CVEFixes: 341                                                             |
| _TypeScript_ |     231 |        231 |        0 |     167 |    63 |       228 |    49 |  3   | CVEFixes: 231                                                             |
| _JSON_       |     117 |        117 |        0 |      94 |    64 |       116 |    37 |  3   | CVEFixes: 117                                                             |

### Excluded Languages (<100 samples)

| Language    | Total | Vuln | CWE | CVSS | Fix Pairs | #CWEs | Source   |
| ----------- | ----: | ---: | --: | ---: | --------: | ----: | -------- |
| XML         |    90 |   90 |  79 |   22 |        88 |    23 | CVEFixes |
| C#          |    76 |   76 |  61 |   41 |        75 |    28 | CVEFixes |
| Rust        |    75 |   75 |  51 |   21 |        74 |    34 | CVEFixes |
| HTML        |    60 |   60 |  52 |   31 |        59 |    15 | CVEFixes |
| Markdown    |    60 |   60 |  48 |   32 |        60 |    27 | CVEFixes |
| YAML        |    44 |   44 |  29 |    9 |        40 |    15 | CVEFixes |
| Perl        |    42 |   42 |  34 |   26 |        42 |    18 | CVEFixes |
| Kotlin      |    27 |   27 |  19 |    9 |        27 |     9 | CVEFixes |
| Swift       |    19 |   19 |  16 |   11 |        19 |    12 | CVEFixes |
| Objective-C |    18 |   18 |  16 |   11 |        18 |    10 | CVEFixes |
| Shell       |    17 |   17 |  14 |   10 |        17 |    10 | CVEFixes |
| Scala       |    14 |   14 |  12 |    9 |        14 |    11 | CVEFixes |
| CSS         |     9 |    9 |   7 |    3 |         9 |     4 | CVEFixes |
| Lua         |     8 |    8 |   6 |    5 |         8 |     5 | CVEFixes |
| SQL         |     8 |    8 |   7 |    4 |         8 |     6 | CVEFixes |
| Unknown     |     7 |    7 |   7 |    3 |         0 |     7 | CVEFixes |

---

## 3. Tier Assignments

┌─────────────────────────────────────────────────────────┐
│ Tier 1 (≥50,000 samples) — Full model training │
│ └─ C 516,562 samples │
├─────────────────────────────────────────────────────────┤
│ Tier 2 (2,000–50,000) — Per-language fine-tuning │
│ ├─ Python 10,483 samples │
│ ├─ C++ 7,548 samples │
│ └─ PHP 2,100 samples │
├─────────────────────────────────────────────────────────┤
│ Tier 3 (<2,000) — Shared multi-language model │
│ ├─ Go, Java, JavaScript, Ruby, TypeScript │
│ ├─ JSON, Other │
│ └─ Total: 3,221 samples │
├─────────────────────────────────────────────────────────┤
│ Excluded (<100) — Insufficient data │
│ └─ 16 languages │
└─────────────────────────────────────────────────────────┘

---

## 4. Stratified Splits (70/15/15)

All splits are stratified by CWE-id where possible, with fallback to binary label stratification.

### Tier 1: C + C++ (combined)

| Task                      |   Train |    Val |   Test |   Total |
| ------------------------- | ------: | -----: | -----: | ------: |
| _VF_ (binary detection)   | 366,899 | 78,605 | 78,606 | 524,110 |
| _CWE_ (classification)    |  35,893 |  7,667 |  7,667 |  51,227 |
| _Severity_ (CVSS scoring) |   1,842 |    367 |    368 |   2,577 |
| _Repair_ (code fixing)    |  26,058 |  5,560 |  5,561 |  37,179 |

### Tier 2: C++

| Task       | Train |   Val |  Test | Total |
| ---------- | ----: | ----: | ----: | ----: |
| _VF_       | 5,317 | 1,115 | 1,116 | 7,548 |
| _CWE_      | 3,687 |   765 |   766 | 5,218 |
| _Severity_ |   269 |    37 |    38 |   344 |
| _Repair_   | 3,734 |   775 |   776 | 5,285 |

### Tier 2: PHP

| Task       | Train | Val | Test | Total |
| ---------- | ----: | --: | ---: | ----: |
| _VF_       | 1,519 | 290 |  291 | 2,100 |
| _CWE_      | 1,379 | 260 |  261 | 1,900 |
| _Severity_ |   892 | 167 |  167 | 1,226 |
| _Repair_   | 1,511 | 289 |  289 | 2,089 |

### Tier 2: Python

| Task       | Train |   Val |  Test |  Total |
| ---------- | ----: | ----: | ----: | -----: |
| _VF_       | 7,388 | 1,547 | 1,548 | 10,483 |
| _CWE_      |   617 |    95 |    96 |    808 |
| _Severity_ |   265 |    33 |    34 |    332 |
| _Repair_   |   577 |    88 |    88 |    753 |

### Tier 3: Shared (Go, Java, JavaScript, Ruby, TypeScript, JSON, Other)

| Task       | Train | Val | Test | Total |
| ---------- | ----: | --: | ---: | ----: |
| _VF_       | 2,324 | 448 |  449 | 3,221 |
| _CWE_      | 1,974 | 373 |  374 | 2,721 |
| _Severity_ | 1,269 | 235 |  235 | 1,739 |
| _Repair_   | 2,307 | 445 |  446 | 3,198 |

---

## 5. Output Files

data/processed/
├── manifest.json # Master summary (counts, tiers, split sizes)
├── tier1_c_cpp/
│ ├── vf/ {train,val,test}.csv # Binary vulnerability detection
│ ├── cwe/ {train,val,test}.csv # CWE multi-class classification
│ ├── severity/{train,val,test}.csv # CVSS severity scoring
│ └── repair/ {train,val,test}.csv # Vulnerable → fixed code pairs
├── tier2_cpp/
│ ├── vf/ {train,val,test}.csv
│ ├── cwe/ {train,val,test}.csv
│ ├── severity/{train,val,test}.csv
│ └── repair/ {train,val,test}.csv
├── tier2_php/
│ ├── vf/ {train,val,test}.csv
│ ├── cwe/ {train,val,test}.csv
│ ├── severity/{train,val,test}.csv
│ └── repair/ {train,val,test}.csv
├── tier2_python/
│ ├── vf/ {train,val,test}.csv
│ ├── cwe/ {train,val,test}.csv
│ ├── severity/{train,val,test}.csv
│ └── repair/ {train,val,test}.csv
└── tier3_shared/
├── vf/ {train,val,test}.csv
├── cwe/ {train,val,test}.csv
├── severity/{train,val,test}.csv
└── repair/ {train,val,test}.csv

---

## 6. Key Observations

### Strengths

•⁠ ⁠*C has massive coverage* — 516K+ samples with 181 unique CWE classes and 186K fix pairs
•⁠ ⁠*Multi-language achieved* — 11 languages in training tiers (up from C/C++ only in Phase 0)
•⁠ ⁠*Fix pairs available* — 198K+ before/after code pairs across languages for the repair task
•⁠ ⁠*CWE diversity* — Strong CWE coverage even in Tier 2/3 languages

### Challenges for Phase 1+

•⁠ ⁠*Class imbalance in C* — Only 9.8% vulnerable (50,873 / 516,562)
•⁠ ⁠*PHP has no non-vulnerable samples* — All 2,100 are vulnerable (need synthetic negatives or different training strategy)
•⁠ ⁠*Severity data is sparse* — Only 6,094 total samples with CVSS scores
•⁠ ⁠*Tier 3 is small* — 3,221 samples shared across 7 languages; the ⁠ <LANG=xxx> ⁠ token prefix strategy is important here

### Bugs Fixed During Phase 0.5

1.⁠ ⁠*BigVul CSV lacked code columns* — Local CSV was metadata-only; now falls back to HuggingFace
2.⁠ ⁠*DiverseVul CWE array crash* — HF dataset returns CWE as lists; ⁠ normalize_cwe() ⁠ now handles arrays
3.⁠ ⁠*⁠ trust_remote_code ⁠ deprecation* — Removed from all ⁠ load_dataset() ⁠ calls
4.⁠ ⁠*Wrong HuggingFace repo IDs* — CVEFixes, MegaVul, VUDENC now use correct repos
5.⁠ ⁠*VUDENC line-level format* — DetectVul/Vudenc uses sequence columns; normalizer now joins lines
6.⁠ ⁠*CSV escaping* — Source code with special characters now properly escaped

---

## 7. Next Steps → Phase 1

Phase 1 trains binary vulnerability detection models. Start with:

⁠ powershell

# Dry run — see what will be trained

python src/models/run_phase1_all_tiers.py --dry-run

# Train all tiers (RTX 4000, ~4-6 hours total)

python src/models/run_phase1_all_tiers.py --bf16
 ⁠

Training order:
1.⁠ ⁠*Tier 1 C/C++* — CodeT5 + GraphCodeBERT + VulBERTa (~2-4 hours)
2.⁠ ⁠*Tier 2 C++/Python/PHP* — Fine-tune winners (~1-2 hours each)
3.⁠ ⁠*Tier 3 Shared* — Multi-language model with ⁠ <LANG=xxx> ⁠ tokens (~1 hour)

---

Generated by Phase 0.5 audit pipeline | Seed: 42 | Split ratios: 70/15/15
