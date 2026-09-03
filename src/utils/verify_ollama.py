#!/usr/bin/env python3
"""
verify_ollama.py — Verify Ollama installation and test a small model.

Tests:
  1. Check if ollama CLI is available
  2. Check if the ollama server is running
  3. Pull a small test model (e.g. tinyllama or phi)
  4. Run a simple prompt and verify response

Usage:
    python -m src.utils.verify_ollama
"""
import subprocess
import sys
import json
import time


def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Command timed out after {timeout}s"


def check_ollama_installed() -> bool:
    """Check if ollama CLI is available."""
    print("[1/4] Checking ollama installation...")
    code, out, err = run_cmd(["ollama", "--version"])
    
    if code == -1:
        print("  ❌ ollama is NOT installed.")
        print()
        print("  Install instructions:")
        print("    macOS:   brew install ollama")
        print("    Linux:   curl -fsSL https://ollama.com/install.sh | sh")
        print("    Manual:  https://ollama.com/download")
        print()
        return False
    
    version = out.strip() or err.strip()
    print(f"  ✅ ollama installed: {version}")
    return True


def check_ollama_running() -> bool:
    """Check if ollama server is running."""
    print("[2/4] Checking ollama server...")
    code, out, err = run_cmd(["ollama", "list"])
    
    if code != 0:
        print("  ⚠️  ollama server may not be running.")
        print("  Start it with: ollama serve &")
        print(f"  Error: {err.strip()}")
        return False
    
    print(f"  ✅ ollama server is running")
    
    # List installed models
    if out.strip():
        lines = out.strip().split("\n")
        print(f"  Currently installed models:")
        for line in lines[:10]:
            print(f"    {line}")
    else:
        print("  No models currently installed.")
    
    return True


def pull_test_model(model: str = "tinyllama") -> bool:
    """Pull a small test model."""
    print(f"[3/4] Pulling test model: {model}...")
    print(f"  (This may take a few minutes on first run)")
    
    code, out, err = run_cmd(["ollama", "pull", model], timeout=300)
    
    if code != 0:
        print(f"  ❌ Failed to pull {model}: {err.strip()}")
        return False
    
    print(f"  ✅ Model '{model}' is ready")
    return True


def test_inference(model: str = "tinyllama") -> bool:
    """Run a simple test prompt."""
    print(f"[4/4] Running test inference with '{model}'...")
    
    prompt = "What is a buffer overflow vulnerability? Answer in one sentence."
    
    code, out, err = run_cmd(
        ["ollama", "run", model, prompt],
        timeout=120
    )
    
    if code != 0:
        print(f"  ❌ Inference failed: {err.strip()}")
        return False
    
    response = out.strip()[:200]
    print(f"  ✅ Response received ({len(out.strip())} chars):")
    print(f"     \"{response}...\"")
    return True


def main():
    print()
    print("=" * 60)
    print("Ollama Verification")
    print("=" * 60)
    print()
    
    if not check_ollama_installed():
        print()
        print("❌ Ollama verification FAILED — not installed.")
        print("   Install Ollama first, then re-run this script.")
        sys.exit(1)
    
    print()
    if not check_ollama_running():
        print()
        print("⚠️  Start ollama server and re-run this script.")
        sys.exit(1)
    
    print()
    if not pull_test_model("tinyllama"):
        print()
        print("❌ Failed to pull test model.")
        sys.exit(1)
    
    print()
    if not test_inference("tinyllama"):
        print()
        print("❌ Test inference failed.")
        sys.exit(1)
    
    print()
    print("=" * 60)
    print("✅ Ollama verification PASSED")
    print("=" * 60)
    print()
    print("Next steps for Phase 1+:")
    print("  ollama pull mistral:7b-instruct")
    print("  ollama pull deepseek-coder:6.7b-instruct")
    print()


if __name__ == "__main__":
    main()
