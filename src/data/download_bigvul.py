"""
download_bigvul.py — Download the BigVul dataset for vulnerability detection.

BigVul (Fan et al., 2020) contains ~188K C/C++ functions with:
  - Vulnerable / non-vulnerable labels
  - CWE-ids (multi-class classification target)
  - CVSS scores (severity scoring target, continuous 0-10)
  - Code diffs, commit messages, etc.

Source: https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset

Usage:
    python src/data/download_bigvul.py [--output-dir data/raw]
"""

import os
import sys
import argparse
import urllib.request
import hashlib


# BigVul dataset hosted on Google Drive — we use a direct-download mirror
# The original CSV is ~120MB
BIGVUL_URLS = {
    # Primary: GitHub release mirror
    "github": "https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv",
}

DEFAULT_FILENAME = "bigvul_all_c_cpp.csv"


def download_file(url: str, dest_path: str) -> bool:
    """Download a file from URL with progress reporting."""
    print(f"Downloading from: {url}")
    print(f"Destination: {dest_path}")

    try:
        # Create a request with a user-agent header
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        with urllib.request.urlopen(req, timeout=120) as response:
            total_size = response.headers.get("Content-Length")
            if total_size:
                total_size = int(total_size)
                print(f"File size: {total_size / (1024*1024):.1f} MB")

            downloaded = 0
            block_size = 8192
            with open(dest_path, "wb") as f:
                while True:
                    chunk = response.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = downloaded / total_size * 100
                        print(
                            f"\r  Progress: {downloaded/(1024*1024):.1f} MB "
                            f"/ {total_size/(1024*1024):.1f} MB ({pct:.1f}%)",
                            end="",
                            flush=True,
                        )

        print(f"\n✅ Download complete: {dest_path}")
        print(f"   File size: {os.path.getsize(dest_path) / (1024*1024):.1f} MB")
        return True

    except Exception as e:
        print(f"\n❌ Download failed: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Download the BigVul dataset for vulnerability detection."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/raw",
        help="Directory to save the dataset (default: data/raw)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if the file already exists",
    )
    args = parser.parse_args()

    # Resolve paths relative to project root
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    output_dir = os.path.join(project_root, args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    dest_path = os.path.join(output_dir, DEFAULT_FILENAME)

    if os.path.exists(dest_path) and not args.force:
        print(f"✅ Dataset already exists at: {dest_path}")
        print(f"   Size: {os.path.getsize(dest_path) / (1024*1024):.1f} MB")
        print("   Use --force to re-download.")
        return

    print("=" * 60)
    print("BigVul Dataset Downloader")
    print("=" * 60)
    print()

    # Try each URL source
    for source_name, url in BIGVUL_URLS.items():
        print(f"Trying source: {source_name}...")
        if download_file(url, dest_path):
            # Verify the file is valid CSV (check first line)
            try:
                with open(dest_path, "r", encoding="utf-8", errors="replace") as f:
                    header = f.readline().strip()
                if "," in header and len(header) > 10:
                    print(f"\n✅ File appears to be valid CSV.")
                    print(f"   Header columns: {len(header.split(','))}")
                    return
                else:
                    print(f"\n⚠️  File doesn't look like a valid CSV. Trying next source...")
                    os.remove(dest_path)
            except Exception:
                pass

    # If all URLs fail, provide manual instructions
    print()
    print("=" * 60)
    print("⚠️  Automatic download failed.")
    print()
    print("MANUAL DOWNLOAD INSTRUCTIONS:")
    print("1. Visit: https://github.com/ZeoVan/MSR_20_Code_Vulnerability_CSV_Dataset")
    print("2. Download 'all_c_cpp_release2.0.csv'")
    print(f"3. Place it at: {dest_path}")
    print()
    print("Alternative — use the HuggingFace mirror:")
    print("  pip install datasets")
    print("  Then use load_and_explore.py which can load from HuggingFace directly.")
    print("=" * 60)
    sys.exit(1)


if __name__ == "__main__":
    main()
