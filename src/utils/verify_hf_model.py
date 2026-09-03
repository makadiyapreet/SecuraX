#!/usr/bin/env python3
"""
verify_hf_model.py — Verify HuggingFace model download and GPU loading.

Tests:
  1. Download microsoft/codebert-base (or specified model)
  2. Load it onto the available device (CUDA / MPS / CPU)
  3. Run a simple forward pass with a code snippet
  4. Report model size, device, and inference time

Usage:
    python -m src.utils.verify_hf_model
    python -m src.utils.verify_hf_model --model microsoft/unixcoder-base
"""
import sys
import time
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import torch
from transformers import AutoTokenizer, AutoModel
from src.config import CODEBERT_MODEL, DEVICE


def verify_model(model_name: str) -> bool:
    """Download, load, and test a HuggingFace model."""
    
    print("=" * 60)
    print("HuggingFace Model Verification")
    print("=" * 60)
    print(f"  Model:  {model_name}")
    print(f"  Device: {DEVICE}")
    print()
    
    # Step 1: Download tokenizer and model
    print("[1/4] Downloading tokenizer...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print(f"  ✅ Tokenizer loaded (vocab size: {tokenizer.vocab_size:,})")
    except Exception as e:
        print(f"  ❌ Tokenizer download failed: {e}")
        return False
    
    print(f"[2/4] Downloading model weights...")
    try:
        model = AutoModel.from_pretrained(model_name)
        param_count = sum(p.numel() for p in model.parameters())
        print(f"  ✅ Model loaded ({param_count:,} parameters, "
              f"{param_count * 4 / 1e6:.1f} MB @ FP32)")
    except Exception as e:
        print(f"  ❌ Model download failed: {e}")
        return False
    
    # Step 2: Move to device
    print(f"[3/4] Moving model to {DEVICE}...")
    try:
        model = model.to(DEVICE)
        model.eval()
        print(f"  ✅ Model on {DEVICE}")
    except Exception as e:
        print(f"  ⚠️  Failed to move to {DEVICE}, falling back to CPU: {e}")
        model = model.to("cpu")
        model.eval()
    
    # Step 3: Test inference
    print("[4/4] Running test inference...")
    test_code = """
    int main() {
        char buf[10];
        strcpy(buf, argv[1]);  // potential buffer overflow
        return 0;
    }
    """
    
    try:
        inputs = tokenizer(
            test_code,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        
        start = time.time()
        with torch.no_grad():
            outputs = model(**inputs)
        elapsed = time.time() - start
        
        # Get the hidden states shape
        if hasattr(outputs, "last_hidden_state"):
            shape = outputs.last_hidden_state.shape
        else:
            shape = outputs[0].shape
        
        print(f"  ✅ Inference successful!")
        print(f"     Output shape: {shape}")
        print(f"     Time: {elapsed*1000:.1f} ms")
        print(f"     Input tokens: {inputs['input_ids'].shape[1]}")
    except Exception as e:
        print(f"  ❌ Inference failed: {e}")
        return False
    
    print()
    print("✅ HuggingFace model verification PASSED")
    print()
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify HuggingFace model loading")
    parser.add_argument(
        "--model", type=str, default=CODEBERT_MODEL,
        help=f"Model to verify (default: {CODEBERT_MODEL})"
    )
    args = parser.parse_args()
    
    # Print system info
    print()
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available:  {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"CUDA device:     {torch.cuda.get_device_name(0)}")
    print(f"MPS available:   {hasattr(torch.backends, 'mps') and torch.backends.mps.is_available()}")
    print()
    
    success = verify_model(args.model)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
