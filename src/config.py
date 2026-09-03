"""
Project-wide configuration constants.
All paths, hyperparameters, and settings live here.
"""
import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
CHECKPOINTS_DIR = MODELS_DIR / "checkpoints"

# ── Dataset ────────────────────────────────────────────────────
# BigVul dataset (Fan et al., MSR 2020)
# Source: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
BIGVUL_FILENAME = "MSR_data_cleaned.csv"
BIGVUL_PATH = RAW_DATA_DIR / BIGVUL_FILENAME

# ── Split Strategy ─────────────────────────────────────────────
# Stratified by CWE-id, reproducible seed
SPLIT_RATIOS = {"train": 0.80, "val": 0.10, "test": 0.10}
RANDOM_SEED = 42

# ── Model Identifiers ─────────────────────────────────────────
CODEBERT_MODEL = "microsoft/codebert-base"
UNIXCODER_MODEL = "microsoft/unixcoder-base"

# ── Ollama Models (system-level, for code refinement) ──────────
OLLAMA_REFINEMENT_MODELS = [
    "mistral:7b-instruct",
    "deepseek-coder:6.7b-instruct",
]

# ── Severity ───────────────────────────────────────────────────
# BigVul provides CVSS v2 scores (continuous 0.0–10.0).
# We bin them into categorical buckets for classification:
SEVERITY_BINS = {
    "Low":      (0.0, 3.9),
    "Medium":   (4.0, 6.9),
    "High":     (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

# ── Device ─────────────────────────────────────────────────────
import torch
if torch.cuda.is_available():
    DEVICE = "cuda"
elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
    DEVICE = "mps"
else:
    DEVICE = "cpu"
