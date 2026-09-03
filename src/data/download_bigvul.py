#!/usr/bin/env python3
"""
download_bigvul.py — Download the BigVul dataset (Fan et al., MSR 2020).

The dataset is hosted on GitHub as a large CSV.
This script downloads it to data/raw/ if not already present.

Usage:
    python -m src.data.download_bigvul
"""
import os
import sys
import requests
from pathlib import Path
from tqdm import tqdm

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import RAW_DATA_DIR, BIGVUL_FILENAME, BIGVUL_PATH


# BigVul CSV hosted on GitHub (Fan et al.)
# This is the cleaned version from the MSR 2020 paper
BIGVUL_URL = (
    "https://raw.githubusercontent.com/"
    "ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/master/"
    "all_c_cpp_release2.0.csv"
)


def download_file(url: str, dest: Path, chunk_size: int = 8192) -> None:
    """Download a file with a progress bar."""
    print(f"Downloading: {url}")
    print(f"Destination: {dest}")
    
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    
    total = int(resp.headers.get("content-length", 0))
    
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    with open(dest, "wb") as f, tqdm(
        total=total, unit="B", unit_scale=True, desc=dest.name
    ) as bar:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            f.write(chunk)
            bar.update(len(chunk))
    
    size_mb = dest.stat().st_size / (1024 * 1024)
    print(f"✅ Download complete: {size_mb:.1f} MB")


def main():
    if BIGVUL_PATH.exists():
        size_mb = BIGVUL_PATH.stat().st_size / (1024 * 1024)
        print(f"✅ Dataset already exists: {BIGVUL_PATH} ({size_mb:.1f} MB)")
        return
    
    print("=" * 60)
    print("BigVul Dataset Downloader")
    print("=" * 60)
    print()
    print("The BigVul dataset (Fan et al., MSR 2020) contains C/C++")
    print("functions labeled with vulnerability flags and CWE-ids,")
    print("extracted from real-world CVE commits.")
    print()
    
    try:
        download_file(BIGVUL_URL, BIGVUL_PATH)
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Download failed: {e}")
        print()
        print("MANUAL DOWNLOAD INSTRUCTIONS:")
        print("1. Go to: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset")
        print(f"2. Download the CSV file")
        print(f"3. Save it as: {BIGVUL_PATH}")
        print()
        print("Alternative: You can also use the BigVul dataset from:")
        print("  https://zenodo.org/ (search 'BigVul')")
        sys.exit(1)


if __name__ == "__main__":
    main()
