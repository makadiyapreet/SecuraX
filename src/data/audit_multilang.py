"""
audit_multilang.py — Phase 0.5: Multi-Language Data Audit & Tiering.

This script:
  1. Loads all five datasets (BigVul, CVEFixes, MegaVul, DiverseVul, VUDENC)
  2. Normalizes each to a common schema
  3. Deduplicates across datasets (by CVE-id + file + function signature)
  4. Counts per language: total samples, VF-labeled, CWE-annotated, CVSS-annotated,
     and before/after fix pairs
  5. Assigns each language to a tier (Tier 1 ≥50K, Tier 2 2K–50K, Tier 3 <2K)
  6. Creates stratified splits per tier/task (70/15/15, by CWE-id, seed=42)
  7. Saves all splits and a manifest.json

Usage:
    python src/data/audit_multilang.py [--output-dir data/processed] [--skip-download]

Output:
    data/processed/
    ├── manifest.json                    # Summary of all counts, tiers, splits
    ├── tier1_c_cpp/
    │   ├── vf/{train,val,test}.csv      # Binary vulnerability detection
    │   ├── cwe/{train,val,test}.csv     # CWE classification
    │   ├── severity/{train,val,test}.csv # Severity scoring
    │   └── repair/{train,val,test}.csv  # Before/after fix pairs
    ├── tier2_python/
    │   └── ...
    ├── tier2_javascript/
    │   └── ...
    └── tier3_shared/
        └── ...
"""

import os
import sys
import gc
import json
import hashlib
import warnings
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

RANDOM_SEED = 42
SPLIT_RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}
MIN_SAMPLES_PER_CLASS = 2

# Tier thresholds
TIER1_MIN = 50_000
TIER2_MIN = 2_000

# Canonical column names (all loaders normalize to this schema)
SCHEMA_COLS = [
    "source_dataset",   # which dataset this came from
    "language",          # normalized language name (C, C++, Python, Java, etc.)
    "func_before",       # source code (vulnerable or not)
    "func_after",        # fixed code (if available, else NaN)
    "vul",               # 1 = vulnerable, 0 = non-vulnerable
    "cwe_id",            # CWE-xxx string (if available, else NaN)
    "cvss_score",        # float 0-10 (if available, else NaN)
    "cve_id",            # CVE identifier for deduplication
    "file_path",         # file path for deduplication
    "func_name",         # function name/signature for deduplication
]

# Language normalization map
LANG_NORM = {
    "c": "C",
    "c/c++": "C",
    "cpp": "C++",
    "c++": "C++",
    "python": "Python",
    "py": "Python",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "php": "PHP",
    "go": "Go",
    "golang": "Go",
    "c#": "C#",
    "csharp": "C#",
    "cs": "C#",
    "ruby": "Ruby",
    "rb": "Ruby",
    "rust": "Rust",
    "swift": "Swift",
    "kotlin": "Kotlin",
}

TARGET_LANGUAGES = {"C", "C++", "Python", "Java", "JavaScript", "PHP", "Go", "C#", "Ruby"}


def normalize_language(lang: str) -> str:
    """Normalize a language string to canonical form."""
    if pd.isna(lang) or lang is None:
        return "Unknown"
    return LANG_NORM.get(str(lang).strip().lower(), str(lang).strip())


def normalize_cwe(cwe) -> Optional[str]:
    """Normalize CWE identifier to 'CWE-XXX' format.
    
    Handles strings, numbers, lists/arrays (takes first element),
    and NaN/None values.
    """
    if cwe is None:
        return None
    # Handle list/array inputs (e.g. from HuggingFace datasets)
    if isinstance(cwe, (list, np.ndarray)):
        if len(cwe) == 0:
            return None
        cwe = cwe[0]  # Take first element
    try:
        if pd.isna(cwe):
            return None
    except (ValueError, TypeError):
        # pd.isna raises on arrays/ambiguous values — treat as valid
        pass
    cwe_str = str(cwe).strip()
    if not cwe_str or cwe_str.lower() in ("nan", "none", "", "0", "unknown", "noinfo", "noinfo "):
        return None
    # Already in CWE-XXX format
    if cwe_str.upper().startswith("CWE-"):
        return cwe_str.upper()
    # Just a number
    try:
        num = int(float(cwe_str))
        if num > 0:
            return f"CWE-{num}"
    except (ValueError, TypeError):
        pass
    return None


def normalize_cvss(score) -> Optional[float]:
    """Normalize CVSS score to float 0-10."""
    if pd.isna(score) or score is None:
        return None
    try:
        val = float(score)
        if 0.0 <= val <= 10.0:
            return val
    except (ValueError, TypeError):
        pass
    return None


def dedup_key(row) -> str:
    """Create a deduplication key from CVE-id + file path + function code hash."""
    parts = []
    # Use CVE-id if available
    cve = str(row.get("cve_id", "")) if pd.notna(row.get("cve_id")) else ""
    parts.append(cve)
    # Use file path if available
    fp = str(row.get("file_path", "")) if pd.notna(row.get("file_path")) else ""
    parts.append(fp)
    # Hash of the function code for fuzzy dedup
    code = str(row.get("func_before", "")) if pd.notna(row.get("func_before")) else ""
    code_hash = hashlib.md5(code.encode("utf-8", errors="replace")).hexdigest()[:16]
    parts.append(code_hash)
    return "|".join(parts)


# ─── Dataset Loaders ─────────────────────────────────────────────────────────


def load_bigvul() -> pd.DataFrame:
    """Load BigVul dataset — C/C++ functions with VF, CWE, CVSS.
    
    Checks if the local CSV has source code columns (func_before / processed_func).
    If not (metadata-only CSV), falls back to the HuggingFace version which
    includes the actual function source code.
    """
    print("\n  [1/5] Loading BigVul...")
    
    csv_path = os.path.join(RAW_DIR, "bigvul_all_c_cpp.csv")
    use_local = False
    
    if os.path.exists(csv_path):
        # Peek at columns to check if source code is present
        df_peek = pd.read_csv(csv_path, nrows=0)
        code_columns = {"func_before", "func_after", "processed_func"}
        has_code = bool(code_columns & set(df_peek.columns))
        
        if has_code:
            print(f"    Loading from local CSV (has code columns): {csv_path}")
            df = pd.read_csv(csv_path, low_memory=False)
            use_local = True
        else:
            print(f"    Local CSV exists but lacks code columns: {list(df_peek.columns)[:8]}...")
            print("    Falling back to HuggingFace for full dataset with source code...")
    
    if not use_local:
        print("    Loading from HuggingFace (bstee615/bigvul)...")
        from datasets import load_dataset
        try:
            ds = load_dataset("bstee615/bigvul")
        except Exception:
            ds = load_dataset("benjis/bigvul")
        dfs = []
        for split_name in ds:
            dfs.append(ds[split_name].to_pandas())
        df = pd.concat(dfs, ignore_index=True)
    
    print(f"    Raw rows: {len(df):,}")
    print(f"    Available columns: {list(df.columns)[:12]}...")
    
    # Map columns to schema
    # BigVul column names vary — check what's available
    code_col = next((c for c in ("func_before", "processed_func", "code", "func")
                     if c in df.columns), None)
    after_col = "func_after" if "func_after" in df.columns else None
    vul_col = "vul" if "vul" in df.columns else "target"
    cve_col = "cve_id" if "cve_id" in df.columns else "CVE ID"
    cwe_col = "cwe_id" if "cwe_id" in df.columns else "CWE ID"
    cvss_col = "cvss_score" if "cvss_score" in df.columns else "score"
    file_col = "file_name" if "file_name" in df.columns else None
    
    if code_col is None:
        print("    ⚠️  No code column found in BigVul! Returning empty.")
        return pd.DataFrame(columns=SCHEMA_COLS)
    
    print(f"    Mapped: code={code_col}, after={after_col}, vul={vul_col}, cwe={cwe_col}")
    
    # Determine language — BigVul is C/C++ only
    # Use 'project_language' or 'lang' column if available, else default to C
    if "lang" in df.columns:
        lang_series = df["lang"].apply(normalize_language)
    elif "project_language" in df.columns:
        lang_series = df["project_language"].apply(normalize_language)
    else:
        lang_series = pd.Series(["C"] * len(df))
    
    result = pd.DataFrame({
        "source_dataset": "BigVul",
        "language": lang_series,
        "func_before": df[code_col].astype(str) if code_col in df.columns else "",
        "func_after": df[after_col].astype(str) if after_col and after_col in df.columns else np.nan,
        "vul": df[vul_col].astype(int) if vul_col in df.columns else 0,
        "cwe_id": df[cwe_col].apply(normalize_cwe) if cwe_col in df.columns else None,
        "cvss_score": df[cvss_col].apply(normalize_cvss) if cvss_col in df.columns else None,
        "cve_id": df[cve_col].astype(str) if cve_col in df.columns else "",
        "file_path": df[file_col].astype(str) if file_col and file_col in df.columns else "",
        "func_name": "",  # BigVul doesn't have clean func names
    })
    
    print(f"    Loaded: {len(result):,} rows, langs: {result['language'].value_counts().to_dict()}")
    return result


def load_cvefixes() -> pd.DataFrame:
    """Load CVEFixes dataset — multi-language vulnerability fixes."""
    print("\n  [2/5] Loading CVEFixes...")
    
    try:
        from datasets import load_dataset
        print("    Loading from HuggingFace (hitoshura25/cvefixes)...")
        # CVEFixes on HF — try multiple known names
        try:
            ds = load_dataset("hitoshura25/cvefixes")
        except Exception:
            try:
                ds = load_dataset("claudios/cvefixes")
            except Exception:
                print("    ⚠️  CVEFixes not found on HuggingFace. Trying local...")
                return _load_cvefixes_local()
        
        if isinstance(ds, dict):
            dfs = [ds[split].to_pandas() for split in ds]
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = ds.to_pandas() if hasattr(ds, 'to_pandas') else ds["train"].to_pandas()
        
        print(f"    Raw rows: {len(df):,}")
        print(f"    Columns: {list(df.columns)[:15]}...")
        
        return _normalize_cvefixes(df)
        
    except Exception as e:
        print(f"    ⚠️  CVEFixes load error: {e}")
        return _load_cvefixes_local()


def _load_cvefixes_local() -> pd.DataFrame:
    """Fallback: try loading CVEFixes from local SQLite or CSV."""
    cvefixes_dir = os.path.join(RAW_DIR, "cvefixes")
    
    # Try SQLite
    db_path = os.path.join(cvefixes_dir, "cvefixes.db")
    if os.path.exists(db_path):
        import sqlite3
        conn = sqlite3.connect(db_path)
        # Query the method_change table which has vulnerable functions
        df = pd.read_sql("""
            SELECT mc.*, cc.cwe_id, cc.cvss2_base_score, cc.cvss3_base_score,
                   cc.cve_id, f.programming_language, f.filename
            FROM method_change mc
            JOIN file_change fc ON mc.file_change_id = fc.file_change_id
            JOIN commits c ON fc.hash = c.hash
            JOIN fixes fx ON c.hash = fx.hash
            JOIN cve cc ON fx.cve_id = cc.cve_id
            JOIN file_change f ON mc.file_change_id = f.file_change_id
        """, conn)
        conn.close()
        return _normalize_cvefixes(df)
    
    print("    ⚠️  CVEFixes: No local data found. Returning empty DataFrame.")
    print("    To download: visit https://github.com/secureIT-project/CVEfixes")
    return pd.DataFrame(columns=SCHEMA_COLS)


def _normalize_cvefixes(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize CVEFixes DataFrame to common schema."""
    # Detect column names (varies by version)
    lang_col = next((c for c in df.columns if c.lower() in 
                     ("programming_language", "language", "lang")), None)
    # Search for code columns — different HF versions use different names
    code_before = next((c for c in df.columns if 
                        ("before" in c.lower() and any(k in c.lower() for k in ("code", "method", "func"))) or
                        c.lower() in ("vulnerable_code", "vulnerable_func", "func_before", "code_before")
                       ), None)
    code_after = next((c for c in df.columns if 
                       ("after" in c.lower() and any(k in c.lower() for k in ("code", "method", "func"))) or
                       c.lower() in ("fixed_code", "fixed_func", "func_after", "code_after", "patched_code")
                      ), None)
    # If still no code columns, check for diff/patch columns
    if not code_before:
        code_before = next((c for c in df.columns if c.lower() in 
                           ("diff", "patch", "code", "source_code")), None)
    cwe_col = next((c for c in df.columns if "cwe" in c.lower() and "id" in c.lower()), None)
    if not cwe_col:
        cwe_col = next((c for c in df.columns if "cwe" in c.lower() and "name" not in c.lower() and "desc" not in c.lower()), None)
    cvss_col = next((c for c in df.columns if "cvss" in c.lower() and "score" in c.lower()), None)
    if not cvss_col:
        cvss_col = next((c for c in df.columns if "cvss" in c.lower() and "base" in c.lower()), None)
    if not cvss_col:
        cvss_col = next((c for c in df.columns if "cvss" in c.lower()), None)
    cve_col = next((c for c in df.columns if "cve" in c.lower() and "id" in c.lower()), None)
    file_col = next((c for c in df.columns if "file" in c.lower() and "name" in c.lower()), None)
    
    print(f"    Mapped columns: lang={lang_col}, code_before={code_before}, "
          f"code_after={code_after}, cwe={cwe_col}, cvss={cvss_col}")
    
    n = len(df)
    result = pd.DataFrame({
        "source_dataset": ["CVEFixes"] * n,
        "language": df[lang_col].apply(normalize_language) if lang_col else ["Unknown"] * n,
        "func_before": df[code_before].astype(str) if code_before else [""] * n,
        "func_after": df[code_after].astype(str) if code_after else [np.nan] * n,
        "vul": [1] * n,  # CVEFixes only contains vulnerable code
        "cwe_id": df[cwe_col].apply(normalize_cwe) if cwe_col else [None] * n,
        "cvss_score": df[cvss_col].apply(normalize_cvss) if cvss_col else [None] * n,
        "cve_id": df[cve_col].astype(str) if cve_col else [""] * n,
        "file_path": df[file_col].astype(str) if file_col else [""] * n,
        "func_name": [""] * n,
    })
    
    print(f"    Normalized: {len(result):,} rows")
    if lang_col:
        print(f"    Languages: {result['language'].value_counts().head(10).to_dict()}")
    return result


def load_megavul() -> pd.DataFrame:
    """Load MegaVul dataset — C/C++ and Java vulnerabilities."""
    print("\n  [3/5] Loading MegaVul...")
    
    try:
        from datasets import load_dataset
        print("    Loading from HuggingFace (hitoshura25/megavul)...")
        try:
            ds = load_dataset("hitoshura25/megavul")
        except Exception:
            try:
                ds = load_dataset("Icyrockton/MegaVul")
            except Exception as e:
                print(f"    ⚠️  MegaVul not found on HuggingFace: {e}")
                return pd.DataFrame(columns=SCHEMA_COLS)
        
        if isinstance(ds, dict):
            dfs = [ds[split].to_pandas() for split in ds]
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = ds["train"].to_pandas()
        
        print(f"    Raw rows: {len(df):,}")
        print(f"    Columns: {list(df.columns)[:15]}...")
        
        # Normalize
        lang_col = next((c for c in df.columns if "lang" in c.lower()), None)
        code_col = next((c for c in df.columns if any(k in c.lower() for k in 
                        ["func_before", "vulnerable_code", "code_before", "func"])), None)
        after_col = next((c for c in df.columns if any(k in c.lower() for k in 
                         ["func_after", "fixed_code", "code_after", "patch"])), None)
        cwe_col = next((c for c in df.columns if "cwe" in c.lower()), None)
        cvss_col = next((c for c in df.columns if "cvss" in c.lower()), None)
        cve_col = next((c for c in df.columns if "cve" in c.lower()), None)
        
        print(f"    Mapped: lang={lang_col}, code={code_col}, after={after_col}, "
              f"cwe={cwe_col}, cvss={cvss_col}")
        
        n = len(df)
        result = pd.DataFrame({
            "source_dataset": ["MegaVul"] * n,
            "language": df[lang_col].apply(normalize_language) if lang_col else ["C"] * n,
            "func_before": df[code_col].astype(str) if code_col else [""] * n,
            "func_after": df[after_col].astype(str) if after_col else [np.nan] * n,
            "vul": [1] * n,  # MegaVul only contains vulnerable functions
            "cwe_id": df[cwe_col].apply(normalize_cwe) if cwe_col else [None] * n,
            "cvss_score": df[cvss_col].apply(normalize_cvss) if cvss_col else [None] * n,
            "cve_id": df[cve_col].astype(str) if cve_col else [""] * n,
            "file_path": "",
            "func_name": "",
        })
        
        print(f"    Loaded: {len(result):,} rows")
        if lang_col:
            print(f"    Languages: {result['language'].value_counts().head(10).to_dict()}")
        return result
        
    except Exception as e:
        print(f"    ⚠️  MegaVul load error: {e}")
        return pd.DataFrame(columns=SCHEMA_COLS)


def load_diversevul() -> pd.DataFrame:
    """Load DiverseVul dataset — C/C++ with cleaner labels."""
    print("\n  [4/5] Loading DiverseVul...")
    
    try:
        from datasets import load_dataset
        print("    Loading from HuggingFace (benjis/diversevul)...")
        try:
            ds = load_dataset("benjis/diversevul")
        except Exception:
            try:
                ds = load_dataset("DiverseVul/diversevul")
            except Exception as e:
                print(f"    ⚠️  DiverseVul not found on HuggingFace: {e}")
                return pd.DataFrame(columns=SCHEMA_COLS)
        
        if isinstance(ds, dict):
            dfs = [ds[split].to_pandas() for split in ds]
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = ds["train"].to_pandas()
        
        print(f"    Raw rows: {len(df):,}")
        print(f"    Columns: {list(df.columns)[:15]}...")
        
        # Normalize — DiverseVul has 'func', 'target', 'cwe', etc.
        code_col = next((c for c in df.columns if c.lower() in 
                        ("func", "func_before", "code", "function")), None)
        vul_col = next((c for c in df.columns if c.lower() in 
                       ("target", "vul", "vulnerable", "label")), None)
        cwe_col = next((c for c in df.columns if "cwe" in c.lower()), None)
        cve_col = next((c for c in df.columns if "cve" in c.lower()), None)
        
        print(f"    Mapped: code={code_col}, vul={vul_col}, cwe={cwe_col}, cve={cve_col}")
        
        n = len(df)
        
        # Handle vul column — may be int, bool, or array-like
        if vul_col and vul_col in df.columns:
            vul_series = pd.to_numeric(df[vul_col], errors="coerce").fillna(0).astype(int)
        else:
            vul_series = pd.Series([0] * n)
        
        # Handle CWE column — may contain lists/arrays from HuggingFace
        if cwe_col and cwe_col in df.columns:
            cwe_series = df[cwe_col].apply(normalize_cwe)
        else:
            cwe_series = pd.Series([None] * n)
        
        # Handle CVE column — may contain lists/arrays
        if cve_col and cve_col in df.columns:
            def safe_str(x):
                if isinstance(x, (list, np.ndarray)):
                    return str(x[0]) if len(x) > 0 else ""
                return str(x) if pd.notna(x) else ""
            cve_series = df[cve_col].apply(safe_str)
        else:
            cve_series = pd.Series([""] * n)
        
        result = pd.DataFrame({
            "source_dataset": ["DiverseVul"] * n,
            "language": ["C"] * n,  # DiverseVul is C/C++ only
            "func_before": df[code_col].astype(str) if code_col else [""] * n,
            "func_after": [np.nan] * n,  # DiverseVul doesn't have fix pairs
            "vul": vul_series,
            "cwe_id": cwe_series,
            "cvss_score": [None] * n,  # DiverseVul doesn't have CVSS
            "cve_id": cve_series,
            "file_path": "",
            "func_name": "",
        })
        
        print(f"    Loaded: {len(result):,} rows")
        print(f"    Vulnerable: {result['vul'].sum():,} / {len(result):,}")
        return result
        
    except Exception as e:
        print(f"    ⚠️  DiverseVul load error: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame(columns=SCHEMA_COLS)


def load_vudenc() -> pd.DataFrame:
    """Load VUDENC dataset — Python vulnerabilities."""
    print("\n  [5/5] Loading VUDENC...")
    
    try:
        from datasets import load_dataset
        print("    Loading from HuggingFace...")
        try:
            ds = load_dataset("DetectVul/Vudenc")
        except Exception:
            try:
                ds = load_dataset("LauraWartworked/VulnerabilityDetection")
            except Exception:
                print("    ⚠️  VUDENC not found on HuggingFace.")
                return _load_vudenc_local()
        
        if isinstance(ds, dict):
            dfs = [ds[split].to_pandas() for split in ds]
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = ds["train"].to_pandas()
        
        print(f"    Raw rows: {len(df):,}")
        return _normalize_vudenc(df)
        
    except Exception as e:
        print(f"    ⚠️  VUDENC load error: {e}")
        return _load_vudenc_local()


def _load_vudenc_local() -> pd.DataFrame:
    """Try loading VUDENC from local files."""
    vudenc_dir = os.path.join(RAW_DIR, "vudenc")
    
    # Check for CSV files
    for fname in os.listdir(vudenc_dir) if os.path.isdir(vudenc_dir) else []:
        if fname.endswith(".csv"):
            df = pd.read_csv(os.path.join(vudenc_dir, fname), low_memory=False)
            return _normalize_vudenc(df)
    
    print("    ⚠️  VUDENC: No local data found.")
    print("    To download: git clone https://github.com/LauraWartschinski/VulnerabilityDetection")
    return pd.DataFrame(columns=SCHEMA_COLS)


def _normalize_vudenc(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize VUDENC DataFrame to common schema.
    
    The DetectVul/Vudenc dataset has a line-level schema:
      - lines: list[str]     (code lines)
      - raw_lines: list[str] (raw code lines)
      - label: list[int]     (per-line vuln labels: 0 or 1)
      - type: list[str]      (per-line vuln type strings)
    
    We join lines into a single code string and use majority-vote for the label.
    """
    print(f"    VUDENC columns: {list(df.columns)}")
    
    # Check if this is the line-level format
    if "lines" in df.columns or "raw_lines" in df.columns:
        print("    Detected line-level format — joining lines into functions...")
        
        code_col = "raw_lines" if "raw_lines" in df.columns else "lines"
        records = []
        
        for idx, row in df.iterrows():
            lines = row.get(code_col, row.get("lines", []))
            labels = row.get("label", [])
            types = row.get("type", [])
            
            # Skip empty rows
            if not isinstance(lines, (list, np.ndarray)) or len(lines) == 0:
                continue
            
            # Join all lines into a single code block
            code = "\n".join(str(l) for l in lines)
            
            # Determine vulnerability: 1 if any line is vulnerable
            if isinstance(labels, (list, np.ndarray)) and len(labels) > 0:
                vul = 1 if any(int(l) == 1 for l in labels) else 0
            else:
                vul = 0
            
            # Get vulnerability type (first non-empty type)
            cwe = None
            if isinstance(types, (list, np.ndarray)):
                for t in types:
                    t_str = str(t).strip()
                    if t_str and t_str.lower() not in ("none", "nan", "", "0"):
                        cwe = t_str
                        break
            
            records.append({
                "source_dataset": "VUDENC",
                "language": "Python",
                "func_before": code,
                "func_after": np.nan,
                "vul": vul,
                "cwe_id": cwe,
                "cvss_score": None,
                "cve_id": "",
                "file_path": "",
                "func_name": "",
            })
        
        result = pd.DataFrame(records)
        vul_count = result["vul"].sum() if len(result) > 0 else 0
        print(f"    Normalized: {len(result):,} rows, vulnerable: {vul_count:,}")
        return result
    
    # Fallback: standard flat format
    code_col = next((c for c in df.columns if any(k in c.lower() for k in 
                    ["code", "func", "snippet"])), None)
    vul_col = next((c for c in df.columns if c.lower() in 
                   ("label", "target", "vul", "vulnerable")), None)
    cwe_col = next((c for c in df.columns if "cwe" in c.lower()), None)
    
    n = len(df)
    result = pd.DataFrame({
        "source_dataset": ["VUDENC"] * n,
        "language": ["Python"] * n,
        "func_before": df[code_col].astype(str) if code_col else [""] * n,
        "func_after": [np.nan] * n,
        "vul": pd.to_numeric(df[vul_col], errors="coerce").fillna(0).astype(int) if vul_col else [0] * n,
        "cwe_id": df[cwe_col].apply(normalize_cwe) if cwe_col else [None] * n,
        "cvss_score": [None] * n,
        "cve_id": [""] * n,
        "file_path": [""] * n,
        "func_name": [""] * n,
    })
    
    print(f"    Normalized: {len(result):,} rows, vulnerable: {result['vul'].sum():,}")
    return result


# ─── Deduplication ───────────────────────────────────────────────────────────


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Deduplicate across datasets using CVE-id + file + code hash.
    
    Priority: keep the row with the most metadata (CWE + CVSS + fix pair).
    """
    print("\n  Deduplicating across datasets...")
    n_before = len(df)
    
    # Create dedup key
    df = df.copy()
    df["_dedup_key"] = df.apply(dedup_key, axis=1)
    
    # Score each row by metadata completeness (higher = keep)
    df["_meta_score"] = (
        df["cwe_id"].notna().astype(int) * 4 +
        df["cvss_score"].notna().astype(int) * 2 +
        df["func_after"].notna().astype(int) * 2 +
        df["cve_id"].apply(lambda x: 1 if pd.notna(x) and str(x).startswith("CVE") else 0)
    )
    
    # Sort by meta_score descending, then keep first
    df = df.sort_values("_meta_score", ascending=False)
    df = df.drop_duplicates(subset=["_dedup_key"], keep="first")
    df = df.drop(columns=["_dedup_key", "_meta_score"])
    df = df.reset_index(drop=True)
    
    n_after = len(df)
    print(f"    Before: {n_before:,} → After: {n_after:,} (removed {n_before - n_after:,} duplicates)")
    
    return df


# ─── Counting & Tiering ─────────────────────────────────────────────────────


def compute_counts(df: pd.DataFrame) -> Dict:
    """Compute per-language counts for the audit report."""
    counts = {}
    
    for lang in sorted(df["language"].unique()):
        lang_df = df[df["language"] == lang]
        
        counts[lang] = {
            "total": len(lang_df),
            "vulnerable": int(lang_df["vul"].sum()),
            "non_vulnerable": int((lang_df["vul"] == 0).sum()),
            "with_cwe": int(lang_df["cwe_id"].notna().sum()),
            "with_cvss": int(lang_df["cvss_score"].notna().sum()),
            "with_fix_pair": int(
                (lang_df["func_after"].notna() & 
                 (lang_df["func_after"] != "") &
                 (lang_df["func_after"] != "nan")).sum()
            ),
            "unique_cwes": int(lang_df["cwe_id"].nunique()),
            "sources": lang_df["source_dataset"].value_counts().to_dict(),
        }
    
    return counts


def assign_tiers(counts: Dict) -> Dict:
    """Assign each language to a tier based on total labeled function count."""
    tiers = {"tier1": [], "tier2": [], "tier3": [], "excluded": []}
    
    for lang, c in counts.items():
        if lang not in TARGET_LANGUAGES and lang != "Unknown":
            # Non-target language — include if it has enough data
            if c["total"] < 100:
                tiers["excluded"].append(lang)
                continue
        
        if lang == "Unknown":
            tiers["excluded"].append(lang)
            continue
            
        total = c["total"]
        if total >= TIER1_MIN:
            tiers["tier1"].append(lang)
        elif total >= TIER2_MIN:
            tiers["tier2"].append(lang)
        elif total >= 100:  # absolute minimum for any useful training
            tiers["tier3"].append(lang)
        else:
            tiers["excluded"].append(lang)
    
    return tiers


# ─── Split Creation ──────────────────────────────────────────────────────────


def create_stratified_splits(
    df: pd.DataFrame,
    stratify_col: str = "cwe_id",
    label_col: str = "vul",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Create 70/15/15 stratified splits.
    
    Stratifies by `stratify_col` if enough samples per class, otherwise by `label_col`.
    Classes with < MIN_SAMPLES_PER_CLASS samples are dropped for stratification
    but kept in the training set.
    """
    df = df.copy()
    
    # Determine stratification column
    if stratify_col in df.columns and df[stratify_col].notna().sum() > 0:
        # Fill NaN CWE with a placeholder for stratification
        strat_key = df[stratify_col].fillna("_UNKNOWN_CWE")
        
        # Check minimum samples per class
        class_counts = strat_key.value_counts()
        valid_classes = class_counts[class_counts >= MIN_SAMPLES_PER_CLASS * 3].index
        
        if len(valid_classes) >= 2:
            # Use CWE stratification for valid classes
            mask_valid = strat_key.isin(valid_classes)
            df_valid = df[mask_valid].copy()
            df_rare = df[~mask_valid].copy()
            
            strat_labels = strat_key[mask_valid]
            
            try:
                train_df, temp_df = train_test_split(
                    df_valid,
                    test_size=(SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]),
                    stratify=strat_labels,
                    random_state=RANDOM_SEED,
                )
                
                temp_strat = strat_key[temp_df.index]
                val_ratio = SPLIT_RATIOS["val"] / (SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"])
                val_df, test_df = train_test_split(
                    temp_df,
                    test_size=(1 - val_ratio),
                    stratify=temp_strat,
                    random_state=RANDOM_SEED,
                )
                
                # Add rare samples to train
                if len(df_rare) > 0:
                    train_df = pd.concat([train_df, df_rare], ignore_index=True)
                
                return (
                    train_df.reset_index(drop=True),
                    val_df.reset_index(drop=True),
                    test_df.reset_index(drop=True),
                )
            except ValueError:
                pass  # Fall through to label-based stratification
    
    # Fallback: stratify by binary label
    if label_col in df.columns:
        try:
            labels = df[label_col].astype(int)
            train_df, temp_df = train_test_split(
                df,
                test_size=(SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"]),
                stratify=labels,
                random_state=RANDOM_SEED,
            )
            temp_labels = temp_df[label_col].astype(int)
            val_ratio = SPLIT_RATIOS["val"] / (SPLIT_RATIOS["val"] + SPLIT_RATIOS["test"])
            val_df, test_df = train_test_split(
                temp_df,
                test_size=(1 - val_ratio),
                stratify=temp_labels,
                random_state=RANDOM_SEED,
            )
            return (
                train_df.reset_index(drop=True),
                val_df.reset_index(drop=True),
                test_df.reset_index(drop=True),
            )
        except ValueError:
            pass
    
    # Last resort: random split
    train_df, temp_df = train_test_split(df, test_size=0.30, random_state=RANDOM_SEED)
    val_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=RANDOM_SEED)
    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


def save_splits_for_task(
    df: pd.DataFrame,
    output_dir: str,
    task: str,
    filter_fn=None,
) -> Dict:
    """Save train/val/test splits for a specific task.
    
    Args:
        df: Input DataFrame (already filtered to the right language/tier)
        output_dir: Base directory for this tier
        task: 'vf', 'cwe', 'severity', or 'repair'
        filter_fn: Optional function to filter the DataFrame for this task
    
    Returns:
        Dict with split counts
    """
    task_dir = os.path.join(output_dir, task)
    os.makedirs(task_dir, exist_ok=True)
    
    # Apply task-specific filter
    task_df = filter_fn(df) if filter_fn else df
    
    if len(task_df) < 6:  # Need at least 2 per split
        print(f"      ⚠️ {task}: only {len(task_df)} samples — skipping splits")
        return {"train": 0, "val": 0, "test": 0, "skipped": True}
    
    # Create splits
    train_df, val_df, test_df = create_stratified_splits(task_df)
    
    # Save — use escapechar for source code with special characters
    csv_opts = {"index": False, "escapechar": "\\", "quoting": 1}  # quoting=1 = QUOTE_ALL
    train_df.to_csv(os.path.join(task_dir, "train.csv"), **csv_opts)
    val_df.to_csv(os.path.join(task_dir, "val.csv"), **csv_opts)
    test_df.to_csv(os.path.join(task_dir, "test.csv"), **csv_opts)
    
    counts = {
        "train": len(train_df),
        "val": len(val_df),
        "test": len(test_df),
        "total": len(task_df),
    }
    
    print(f"      {task}: train={counts['train']:,} / val={counts['val']:,} / test={counts['test']:,}")
    return counts


# ─── Main Audit Pipeline ────────────────────────────────────────────────────


def run_audit(output_dir: str = None):
    """Run the full Phase 0.5 multi-language data audit."""
    
    if output_dir is None:
        output_dir = PROCESSED_DIR
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 70)
    print("  SecuraX — Phase 0.5: Multi-Language Data Audit & Tiering")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)
    
    # ── Step 1: Load all datasets ────────────────────────────────────────
    print("\n" + "─" * 70)
    print("  STEP 1: Loading datasets")
    print("─" * 70)
    
    all_dfs = []
    
    # Load each dataset, catch errors individually
    for loader_name, loader_fn in [
        ("BigVul", load_bigvul),
        ("CVEFixes", load_cvefixes),
        ("MegaVul", load_megavul),
        ("DiverseVul", load_diversevul),
        ("VUDENC", load_vudenc),
    ]:
        try:
            df = loader_fn()
            if len(df) > 0:
                all_dfs.append(df)
                print(f"    ✅ {loader_name}: {len(df):,} rows")
            else:
                print(f"    ⚠️ {loader_name}: 0 rows (empty)")
        except Exception as e:
            print(f"    ❌ {loader_name} failed: {e}")
        gc.collect()
    
    if not all_dfs:
        print("\n  ❌ No datasets loaded! Cannot continue.")
        print("  Make sure at least BigVul is available (data/raw/bigvul_all_c_cpp.csv)")
        sys.exit(1)
    
    # Combine
    combined = pd.concat(all_dfs, ignore_index=True)
    print(f"\n  Combined: {len(combined):,} total rows from {len(all_dfs)} datasets")
    print(f"  Sources: {combined['source_dataset'].value_counts().to_dict()}")
    
    # Clean: drop rows with empty/missing code
    combined = combined[combined["func_before"].notna() & (combined["func_before"] != "") & (combined["func_before"] != "nan")]
    combined = combined.reset_index(drop=True)
    print(f"  After removing empty code: {len(combined):,} rows")
    
    # ── Step 2: Deduplicate ──────────────────────────────────────────────
    print("\n" + "─" * 70)
    print("  STEP 2: Cross-dataset deduplication")
    print("─" * 70)
    
    combined = deduplicate(combined)
    
    # ── Step 3: Count per language ───────────────────────────────────────
    print("\n" + "─" * 70)
    print("  STEP 3: Per-language counts")
    print("─" * 70)
    
    counts = compute_counts(combined)
    
    print(f"\n  {'Language':<15} {'Total':>10} {'Vuln':>10} {'NonVuln':>10} "
          f"{'CWE':>8} {'CVSS':>8} {'FixPairs':>10} {'#CWEs':>6}")
    print(f"  {'─'*13}  {'─'*10} {'─'*10} {'─'*10} {'─'*8} {'─'*8} {'─'*10} {'─'*6}")
    
    for lang in sorted(counts.keys(), key=lambda l: counts[l]["total"], reverse=True):
        c = counts[lang]
        print(f"  {lang:<15} {c['total']:>10,} {c['vulnerable']:>10,} {c['non_vulnerable']:>10,} "
              f"{c['with_cwe']:>8,} {c['with_cvss']:>8,} {c['with_fix_pair']:>10,} {c['unique_cwes']:>6}")
    
    # ── Step 4: Assign tiers ─────────────────────────────────────────────
    print("\n" + "─" * 70)
    print("  STEP 4: Tier assignment")
    print("─" * 70)
    
    tiers = assign_tiers(counts)
    
    print(f"\n  Tier 1 (≥{TIER1_MIN:,} samples): {tiers['tier1'] or 'None'}")
    print(f"  Tier 2 ({TIER2_MIN:,}–{TIER1_MIN:,} samples): {tiers['tier2'] or 'None'}")
    print(f"  Tier 3 (<{TIER2_MIN:,} samples): {tiers['tier3'] or 'None'}")
    print(f"  Excluded (<100 samples): {tiers['excluded'] or 'None'}")
    
    # ── Step 5: Create splits per tier ───────────────────────────────────
    print("\n" + "─" * 70)
    print("  STEP 5: Creating stratified splits per tier/task")
    print("─" * 70)
    
    manifest = {
        "generated_at": datetime.now().isoformat(),
        "random_seed": RANDOM_SEED,
        "split_ratios": SPLIT_RATIOS,
        "tier_thresholds": {"tier1_min": TIER1_MIN, "tier2_min": TIER2_MIN},
        "per_language_counts": counts,
        "tier_assignments": tiers,
        "splits": {},
    }
    
    # Task filters
    def vf_filter(d):
        """All samples (vuln + non-vuln) for binary detection."""
        return d
    
    def cwe_filter(d):
        """Only vulnerable samples with valid CWE-id."""
        return d[(d["vul"] == 1) & d["cwe_id"].notna()].copy()
    
    def severity_filter(d):
        """Only vulnerable samples with valid CVSS score."""
        return d[(d["vul"] == 1) & d["cvss_score"].notna()].copy()
    
    def repair_filter(d):
        """Only vulnerable samples with before/after fix pairs."""
        return d[
            (d["vul"] == 1) & 
            d["func_after"].notna() & 
            (d["func_after"] != "") &
            (d["func_after"] != "nan")
        ].copy()
    
    tasks = [
        ("vf", vf_filter),
        ("cwe", cwe_filter),
        ("severity", severity_filter),
        ("repair", repair_filter),
    ]
    
    # ── Tier 1 ───────────────────────────────────────────────────────────
    for lang in tiers["tier1"]:
        tier_key = f"tier1_{lang.lower().replace('+', 'p').replace('#', 'sharp')}"
        tier_dir = os.path.join(output_dir, tier_key)
        os.makedirs(tier_dir, exist_ok=True)
        
        # For C/C++, combine both C and C++ if they're both Tier 1
        if lang in ("C", "C++"):
            lang_df = combined[combined["language"].isin(["C", "C++"])].copy()
            tier_key = "tier1_c_cpp"
            tier_dir = os.path.join(output_dir, tier_key)
            os.makedirs(tier_dir, exist_ok=True)
        else:
            lang_df = combined[combined["language"] == lang].copy()
        
        print(f"\n    [{tier_key}] {lang} — {len(lang_df):,} total samples")
        
        manifest["splits"][tier_key] = {"languages": [lang], "tier": 1, "tasks": {}}
        if lang in ("C", "C++"):
            manifest["splits"][tier_key]["languages"] = ["C", "C++"]
        
        for task_name, task_filter in tasks:
            split_counts = save_splits_for_task(lang_df, tier_dir, task_name, task_filter)
            manifest["splits"][tier_key]["tasks"][task_name] = split_counts
        
        # Avoid processing C and C++ separately if combined
        if lang in ("C", "C++"):
            # Remove C++ from tier1 processing to avoid double
            if "C++" in tiers["tier1"]:
                tiers["tier1"] = [l for l in tiers["tier1"] if l != "C++"]
            break
    
    # ── Tier 2 ───────────────────────────────────────────────────────────
    for lang in tiers["tier2"]:
        tier_key = f"tier2_{lang.lower().replace('+', 'p').replace('#', 'sharp')}"
        tier_dir = os.path.join(output_dir, tier_key)
        os.makedirs(tier_dir, exist_ok=True)
        
        lang_df = combined[combined["language"] == lang].copy()
        print(f"\n    [{tier_key}] {lang} — {len(lang_df):,} total samples")
        
        manifest["splits"][tier_key] = {"languages": [lang], "tier": 2, "tasks": {}}
        
        for task_name, task_filter in tasks:
            split_counts = save_splits_for_task(lang_df, tier_dir, task_name, task_filter)
            manifest["splits"][tier_key]["tasks"][task_name] = split_counts
    
    # ── Tier 3 (shared) ──────────────────────────────────────────────────
    if tiers["tier3"]:
        tier_key = "tier3_shared"
        tier_dir = os.path.join(output_dir, tier_key)
        os.makedirs(tier_dir, exist_ok=True)
        
        lang_df = combined[combined["language"].isin(tiers["tier3"])].copy()
        print(f"\n    [{tier_key}] {tiers['tier3']} — {len(lang_df):,} total samples")
        
        # Add language token column for Tier 3
        lang_df["lang_token"] = lang_df["language"].apply(lambda l: f"<LANG={l.lower()}>")
        
        manifest["splits"][tier_key] = {
            "languages": tiers["tier3"], "tier": 3, "tasks": {}
        }
        
        for task_name, task_filter in tasks:
            split_counts = save_splits_for_task(lang_df, tier_dir, task_name, task_filter)
            manifest["splits"][tier_key]["tasks"][task_name] = split_counts
    
    # ── Save manifest ────────────────────────────────────────────────────
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    
    print(f"\n  ✅ Manifest saved: {manifest_path}")
    
    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  PHASE 0.5 AUDIT COMPLETE")
    print("=" * 70)
    print(f"\n  Total deduplicated samples: {len(combined):,}")
    print(f"  Languages with data: {len(counts)}")
    print(f"  Tier 1 languages: {tiers['tier1']}")
    print(f"  Tier 2 languages: {tiers['tier2']}")
    print(f"  Tier 3 languages: {tiers['tier3']}")
    print(f"  Excluded: {tiers['excluded']}")
    print(f"\n  All splits saved to: {output_dir}/")
    print(f"  Manifest: {manifest_path}")
    
    return manifest


# ─── CLI ─────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Phase 0.5: Multi-Language Data Audit & Tiering for SecuraX."
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help=f"Output directory for processed splits (default: {PROCESSED_DIR})",
    )
    args = parser.parse_args()
    
    manifest = run_audit(output_dir=args.output_dir)