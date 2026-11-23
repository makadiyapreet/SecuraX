# SecuraX Held-Out Real Data Test Bed (CVEFixes)

**Generated:** 2026-11-07  
**Source:** Genuine in-the-wild vulnerability fixes from CVEFixes git commits.

Each language test bed consists of strict before/after commit pairs:
- **Before-Patch Function (`label = 1`):** Vulnerable implementation as reported in CVE.
- **After-Patch Function (`label = 0`):** Secure remediation committed by project maintainers.

| Language | Pairs | Total Samples | Vuln Samples | Patched Samples | Dataset File |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `php` | 50 | 100 | 50 | 50 | `php.jsonl` |
| `python` | 50 | 100 | 50 | 50 | `python.jsonl` |
| `cpp` | 50 | 100 | 50 | 50 | `cpp.jsonl` |
| `javascript` | 50 | 100 | 50 | 50 | `javascript.jsonl` |
| `java` | 50 | 100 | 50 | 50 | `java.jsonl` |
