"""
verify_models.py — Verify that all required models can be loaded locally.

Models verified:
  1. Salesforce/codet5-base          (encoder for detection)
  2. microsoft/graphcodebert-base    (encoder for detection)
  3. mistralai/Mistral-7B-Instruct-v0.3  (LLM for code refinement, 4-bit)
  4. deepseek-ai/deepseek-coder-6.7b-instruct (LLM for refinement, 4-bit)

Reports:
  - Whether each model loads successfully
  - GPU memory usage before/after loading
  - Total VRAM required
  - Fallback recommendations if memory is insufficient

Usage:
    python src/models/verify_models.py [--skip-large]
"""

import os
import sys
import gc
import argparse
import time

import torch


def get_gpu_info() -> dict:
    """Get GPU information and memory stats."""
    info = {"available": torch.cuda.is_available()}

    if info["available"]:
        info["device_name"] = torch.cuda.get_device_name(0)
        info["total_memory_gb"] = torch.cuda.get_device_properties(0).total_mem / (1024**3)
        info["allocated_gb"] = torch.cuda.memory_allocated(0) / (1024**3)
        info["reserved_gb"] = torch.cuda.memory_reserved(0) / (1024**3)
        info["free_gb"] = info["total_memory_gb"] - info["allocated_gb"]
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        info["device_name"] = "Apple Silicon (MPS)"
        info["mps"] = True
        # MPS doesn't expose detailed memory stats the same way
        info["total_memory_gb"] = -1  # Unknown
        info["note"] = "MPS backend — memory stats limited"

    return info


def clear_gpu_memory():
    """Clear GPU memory cache."""
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        torch.cuda.synchronize()


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def verify_codet5():
    """Verify CodeT5-base can be loaded."""
    print_section("MODEL 1: Salesforce/codet5-base")

    model_name = "Salesforce/codet5-base"
    print(f"\n  Model: {model_name}")
    print(f"  Type:  Encoder-Decoder (T5-based)")
    print(f"  Use:   Vulnerability detection & classification")
    print(f"  Size:  ~220M parameters")

    try:
        from transformers import RobertaTokenizer, AutoModelForSeq2SeqLM

        print(f"\n  Loading tokenizer...", end=" ", flush=True)
        # use_fast=False required for transformers v5.x compatibility
        tokenizer = RobertaTokenizer.from_pretrained(model_name, use_fast=False)
        print("✅")

        print(f"  Loading model...", end=" ", flush=True)
        start_time = time.time()

        # Load to GPU if available, else CPU
        device = "cuda" if torch.cuda.is_available() else "cpu"
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = "mps"

        model = AutoModelForSeq2SeqLM.from_pretrained(model_name).to(device)
        load_time = time.time() - start_time
        print(f"✅ ({load_time:.1f}s)")

        # Quick inference test
        print(f"  Testing inference...", end=" ", flush=True)
        inputs = tokenizer(
            "int main() { char buf[10]; gets(buf); return 0; }",
            return_tensors="pt",
            max_length=512,
            truncation=True,
        ).to(device)

        with torch.no_grad():
            outputs = model.generate(**inputs, max_length=10)

        decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"✅ (output: '{decoded[:50]}')")

        # Memory stats
        param_count = sum(p.numel() for p in model.parameters())
        print(f"\n  Parameters:    {param_count:,}")
        print(f"  Device:        {device}")
        if torch.cuda.is_available():
            mem = torch.cuda.memory_allocated(0) / (1024**3)
            print(f"  GPU Memory:    {mem:.2f} GB")

        # Cleanup
        del model, tokenizer, inputs, outputs
        clear_gpu_memory()

        return True, None

    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False, str(e)


def verify_graphcodebert():
    """Verify GraphCodeBERT can be loaded."""
    print_section("MODEL 2: microsoft/graphcodebert-base")

    model_name = "microsoft/graphcodebert-base"
    print(f"\n  Model: {model_name}")
    print(f"  Type:  Encoder-only (RoBERTa-based)")
    print(f"  Use:   Vulnerability detection (code understanding)")
    print(f"  Size:  ~125M parameters")

    try:
        from transformers import AutoTokenizer, AutoModel

        print(f"\n  Loading tokenizer...", end=" ", flush=True)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print("✅")

        print(f"  Loading model...", end=" ", flush=True)
        start_time = time.time()

        device = "cuda" if torch.cuda.is_available() else "cpu"
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = "mps"

        model = AutoModel.from_pretrained(model_name).to(device)
        load_time = time.time() - start_time
        print(f"✅ ({load_time:.1f}s)")

        # Quick inference test
        print(f"  Testing inference...", end=" ", flush=True)
        inputs = tokenizer(
            "int main() { char buf[10]; gets(buf); return 0; }",
            return_tensors="pt",
            max_length=512,
            truncation=True,
        ).to(device)

        with torch.no_grad():
            outputs = model(**inputs)

        print(f"✅ (hidden_size: {outputs.last_hidden_state.shape[-1]})")

        # Memory stats
        param_count = sum(p.numel() for p in model.parameters())
        print(f"\n  Parameters:    {param_count:,}")
        print(f"  Device:        {device}")
        if torch.cuda.is_available():
            mem = torch.cuda.memory_allocated(0) / (1024**3)
            print(f"  GPU Memory:    {mem:.2f} GB")

        # Cleanup
        del model, tokenizer, inputs, outputs
        clear_gpu_memory()

        return True, None

    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False, str(e)


def verify_mistral_7b():
    """Verify Mistral-7B-Instruct can be loaded with 4-bit quantization."""
    print_section("MODEL 3: mistralai/Mistral-7B-Instruct-v0.3 (4-bit)")

    model_name = "mistralai/Mistral-7B-Instruct-v0.3"
    print(f"\n  Model: {model_name}")
    print(f"  Type:  Decoder-only (Mistral architecture)")
    print(f"  Use:   Code refinement / fixing (Person B)")
    print(f"  Size:  ~7B parameters (4-bit ≈ 5GB VRAM)")
    print(f"  Quant: 4-bit via bitsandbytes (NF4)")

    # Check if CUDA is available (bitsandbytes requires CUDA)
    if not torch.cuda.is_available():
        print(f"\n  ⚠️  CUDA not available — 4-bit quantization requires NVIDIA GPU.")
        print(f"  Checking MPS (Apple Silicon)...")

        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            print(f"  MPS available — but bitsandbytes 4-bit does NOT support MPS.")
            print(f"  FALLBACK OPTIONS:")
            print(f"    1. Load in float16 on MPS (needs ~14GB unified memory)")
            print(f"    2. Use GGUF format with llama-cpp-python (4-bit on CPU/Metal)")
            print(f"    3. Use a smaller model (e.g., deepseek-coder-1.3b-instruct)")
            return False, "No CUDA GPU — MPS does not support bitsandbytes 4-bit"
        else:
            print(f"  No GPU available. Model requires GPU for practical use.")
            return False, "No GPU available"

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

        # 4-bit quantization config
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

        print(f"\n  Loading tokenizer...", end=" ", flush=True)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print("✅")

        print(f"  Loading model (4-bit, this may take a few minutes)...", flush=True)
        start_time = time.time()

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.float16,
        )
        load_time = time.time() - start_time
        print(f"  ✅ Loaded in {load_time:.1f}s")

        # Quick inference test
        print(f"  Testing inference...", end=" ", flush=True)
        prompt = "[INST] Fix this vulnerable C code: char buf[10]; gets(buf); [/INST]"
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=50, do_sample=False)

        decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"✅")
        print(f"  Sample output: '{decoded[:100]}...'")

        # Memory stats
        if torch.cuda.is_available():
            mem = torch.cuda.memory_allocated(0) / (1024**3)
            print(f"\n  GPU Memory:    {mem:.2f} GB")

        # Cleanup
        del model, tokenizer, inputs, outputs
        clear_gpu_memory()

        return True, None

    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        print(f"\n  FALLBACK OPTIONS:")
        print(f"    1. Try smaller model: mistralai/Mistral-7B-Instruct-v0.1")
        print(f"    2. Use CPU offloading: device_map='auto' with max_memory")
        print(f"    3. Use a smaller LLM for refinement")
        return False, str(e)


def verify_deepseek_coder():
    """Verify DeepSeek-Coder-Instruct can be loaded with 4-bit quantization."""
    print_section("MODEL 4: deepseek-ai/deepseek-coder-6.7b-instruct (4-bit)")

    model_name = "deepseek-ai/deepseek-coder-6.7b-instruct"
    print(f"\n  Model: {model_name}")
    print(f"  Type:  Decoder-only (code-specialized)")
    print(f"  Use:   Code refinement / fixing (Person B)")
    print(f"  Size:  ~6.7B parameters (4-bit ≈ 4.5GB VRAM)")
    print(f"  Quant: 4-bit via bitsandbytes (NF4)")

    # Check if CUDA is available
    if not torch.cuda.is_available():
        print(f"\n  ⚠️  CUDA not available — 4-bit quantization requires NVIDIA GPU.")

        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            print(f"  MPS available — but bitsandbytes 4-bit does NOT support MPS.")
            print(f"  FALLBACK OPTIONS:")
            print(f"    1. Load in float16 on MPS (needs ~13GB unified memory)")
            print(f"    2. Use smaller variant: deepseek-ai/deepseek-coder-1.3b-instruct")
            print(f"    3. Use GGUF format with llama-cpp-python")

            # Try loading the 1.3B variant as fallback
            print(f"\n  Attempting fallback: deepseek-coder-1.3b-instruct on MPS...")
            return _verify_deepseek_1b_mps()
        else:
            return False, "No GPU available"

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

        print(f"\n  Loading tokenizer...", end=" ", flush=True)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print("✅")

        print(f"  Loading model (4-bit, this may take a few minutes)...", flush=True)
        start_time = time.time()

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.float16,
            trust_remote_code=True,
        )
        load_time = time.time() - start_time
        print(f"  ✅ Loaded in {load_time:.1f}s")

        # Quick inference test
        print(f"  Testing inference...", end=" ", flush=True)
        prompt = "Fix the vulnerability in this code:\n```c\nchar buf[10]; gets(buf);\n```"
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=50, do_sample=False)

        decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"✅")
        print(f"  Sample output: '{decoded[:100]}...'")

        # Memory stats
        if torch.cuda.is_available():
            mem = torch.cuda.memory_allocated(0) / (1024**3)
            print(f"\n  GPU Memory:    {mem:.2f} GB")

        # Cleanup
        del model, tokenizer, inputs, outputs
        clear_gpu_memory()

        return True, None

    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        print(f"\n  FALLBACK: Try deepseek-ai/deepseek-coder-1.3b-instruct")
        return False, str(e)


def _verify_deepseek_1b_mps():
    """Fallback: verify DeepSeek-Coder 1.3B on MPS."""
    model_name = "deepseek-ai/deepseek-coder-1.3b-instruct"
    print(f"\n  Fallback Model: {model_name}")
    print(f"  Size: ~1.3B parameters (~2.6GB in float16)")

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM

        print(f"  Loading tokenizer...", end=" ", flush=True)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        print("✅")

        print(f"  Loading model (float16 on MPS)...", end=" ", flush=True)
        start_time = time.time()

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16,
            trust_remote_code=True,
        ).to("mps")
        load_time = time.time() - start_time
        print(f"✅ ({load_time:.1f}s)")

        # Quick inference test
        print(f"  Testing inference...", end=" ", flush=True)
        prompt = "Fix this: char buf[10]; gets(buf);"
        inputs = tokenizer(prompt, return_tensors="pt").to("mps")

        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=30, do_sample=False)

        decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"✅")
        print(f"  Sample output: '{decoded[:80]}...'")

        del model, tokenizer, inputs, outputs
        clear_gpu_memory()

        return True, "Used 1.3B fallback on MPS"

    except Exception as e:
        print(f"  ❌ Fallback also failed: {e}")
        return False, str(e)


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Verify all required models can be loaded locally."
    )
    parser.add_argument(
        "--skip-large",
        action="store_true",
        help="Skip large LLMs (Mistral-7B, DeepSeek-6.7B) — only verify encoders",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  MODEL VERIFICATION — Phase 0")
    print("  Automated Code Vulnerability Detection Project")
    print("=" * 60)

    # GPU info
    gpu_info = get_gpu_info()
    print(f"\n  GPU Available:     {gpu_info['available']}")
    if gpu_info["available"]:
        print(f"  GPU Device:        {gpu_info['device_name']}")
        if gpu_info.get("total_memory_gb", -1) > 0:
            print(f"  Total VRAM:        {gpu_info['total_memory_gb']:.1f} GB")
    elif gpu_info.get("mps"):
        print(f"  GPU Device:        {gpu_info['device_name']}")
        print(f"  Note:              {gpu_info.get('note', '')}")

    # Track results
    results = {}

    # 1. CodeT5
    success, error = verify_codet5()
    results["CodeT5-base"] = {"success": success, "error": error}

    # 2. GraphCodeBERT
    success, error = verify_graphcodebert()
    results["GraphCodeBERT-base"] = {"success": success, "error": error}

    # 3 & 4. Large LLMs
    if not args.skip_large:
        success, error = verify_mistral_7b()
        results["Mistral-7B-Instruct (4-bit)"] = {"success": success, "error": error}

        success, error = verify_deepseek_coder()
        results["DeepSeek-Coder-6.7B (4-bit)"] = {"success": success, "error": error}
    else:
        print(f"\n  ⏩ Skipping large LLMs (--skip-large flag)")
        results["Mistral-7B-Instruct (4-bit)"] = {"success": None, "error": "Skipped"}
        results["DeepSeek-Coder-6.7B (4-bit)"] = {"success": None, "error": "Skipped"}

    # Summary
    print_section("VERIFICATION SUMMARY")
    print(f"\n  {'Model':<35} {'Status':<10} {'Notes'}")
    print(f"  {'-'*70}")
    for model_name, result in results.items():
        if result["success"] is True:
            status = "✅ PASS"
        elif result["success"] is False:
            status = "❌ FAIL"
        else:
            status = "⏩ SKIP"
        notes = result["error"] or ""
        print(f"  {model_name:<35} {status:<10} {notes}")

    # Final GPU memory
    if torch.cuda.is_available():
        print(f"\n  Final GPU memory allocated: "
              f"{torch.cuda.memory_allocated(0)/(1024**3):.2f} GB")

    failed = [k for k, v in results.items() if v["success"] is False]
    if failed:
        print(f"\n  ⚠️  {len(failed)} model(s) failed to load.")
        print(f"  See FALLBACK OPTIONS above for alternatives.")
    else:
        passed = [k for k, v in results.items() if v["success"] is True]
        print(f"\n  ✅ {len(passed)} model(s) verified successfully.")

    print("=" * 60)


if __name__ == "__main__":
    main()
