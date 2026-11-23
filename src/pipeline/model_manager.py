"""
model_manager.py — Phase 5: Local Neural Model Manager for Phases 1-3.

Loads and caches PyTorch + PEFT models for:
  - Phase 1: Binary Vulnerability Detection (VF) with per-tier optimal thresholds
  - Phase 2: 15-Class CWE Classification (MITRE semantic grouping)
  - Phase 3: CVSS Severity Scoring (0.0 to 10.0 regression)

Supports lazy-loading, CPU / MPS / CUDA auto-detection, and graceful fallbacks.
"""

import os
import json
import logging
import warnings
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

# Suppress HuggingFace model weight initialization and PEFT deprecation warnings
warnings.filterwarnings("ignore")
import transformers
transformers.logging.set_verbosity_error()

import torch
from transformers import AutoTokenizer

from src.data.cwe_taxonomy import (
    CWE_SEMANTIC_GROUPS,
    CLASS_NAMES,
    DEFAULT_GROUP_REPRESENTATIVE,
    resolve_cwe_prediction,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "models" / "saved"
PRETRAINED_DIR = PROJECT_ROOT / "models" / "pretrained" / "graphcodebert-base"
CODET5_DIR = PROJECT_ROOT / "models" / "pretrained" / "codet5-base"

logger = logging.getLogger("model_manager")


def _detect_backbone(checkpoint_dir: Path) -> str:
    """Detect whether checkpoint adapter targets CodeT5 or GraphCodeBERT."""
    adapter_cfg = checkpoint_dir / "adapter_config.json"
    if adapter_cfg.is_file():
        try:
            with open(adapter_cfg, "r") as f:
                data = json.load(f)
            targets = data.get("target_modules", [])
            if any(t in ("q", "k", "v", "o") for t in targets) and not any(t in ("query", "key", "value", "dense") for t in targets):
                return "codet5"
        except Exception:
            pass
    if "codet5" in checkpoint_dir.name.lower():
        return "codet5"
    return "graphcodebert"

# Phase 1 Optimal Classification Thresholds (from Phase 1 ROC/PR analysis)
PHASE1_THRESHOLDS = {
    "tier1_c_cpp": 0.70,
    "tier2_cpp": 0.10,
    "tier2_python": 0.15,
    "tier2_php": 0.10,
    "tier3_shared": 0.50,
}

# Authoritative 15 MITRE Semantic Groups from Phase 2
SEMANTIC_GROUPS = CLASS_NAMES
PRIMARY_CWE_MAP = DEFAULT_GROUP_REPRESENTATIVE


# CWE-1000 Baseline Impact Benchmarks for Empirical Calibration
CWE_SEVERITY_BENCHMARK: Dict[str, float] = {
    "CWE-78": 9.3,   # OS Command Injection
    "CWE-94": 9.2,   # Code Injection
    "CWE-502": 9.0,  # Deserialization of Untrusted Data
    "CWE-89": 8.5,   # SQL Injection
    "CWE-119": 7.8,  # Buffer Overflow
    "CWE-120": 7.8,  # Classic Buffer Overflow
    "CWE-787": 8.2,  # Out-of-bounds Write
    "CWE-125": 7.1,  # Out-of-bounds Read
    "CWE-416": 7.5,  # Use After Free
    "CWE-415": 7.5,  # Double Free
    "CWE-476": 7.0,  # NULL Pointer Dereference
    "CWE-798": 7.5,  # Hardcoded Credentials
    "CWE-287": 7.5,  # Improper Authentication
    "CWE-284": 7.3,  # Improper Access Control
    "CWE-732": 7.1,  # Incorrect Permission Assignment
    "CWE-190": 7.0,  # Integer Overflow
    "CWE-79": 6.1,   # Cross-Site Scripting (XSS)
    "CWE-22": 6.5,   # Path Traversal
    "CWE-601": 5.8,  # Open Redirect
    "CWE-327": 5.9,  # Broken/Risky Cryptography
    "CWE-362": 5.9,  # Race Condition
    "CWE-400": 5.3,  # Uncontrolled Resource Consumption
    "CWE-772": 5.0,  # Missing Release of Resource
    "CWE-20": 5.0,   # Improper Input Validation
    "CWE-200": 4.8,  # Information Exposure
    "CWE-209": 4.5,  # Information Exposure Through Error Message
    "CWE-369": 3.5,  # Divide By Zero
}

GROUP_SEVERITY_BENCHMARK: Dict[str, float] = {
    "Buffer-Overflow": 7.8,
    "OOB-Read": 7.1,
    "OOB-Write": 8.2,
    "Use-After-Free": 7.5,
    "Double-Free": 7.5,
    "NULL-Deref": 7.0,
    "Integer-Issues": 7.0,
    "Input-Validation": 7.2,
    "Info-Exposure": 4.8,
    "Access-Control": 7.4,
    "Crypto-Issues": 5.9,
    "Resource-Mgmt": 5.2,
    "Race-Condition": 5.9,
    "Path-Traversal": 6.5,
    "Other-Security": 6.0,
}


def get_cvss_band(score: float) -> str:
    """Map continuous CVSS score to standard CVSS severity band."""
    if score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


class LocalModelManager:
    """Manages loading, caching, and inference for Phases 1-3 local neural models."""

    def __init__(self, device: Optional[str] = None):
        if device:
            self.device = torch.device(device)
        else:
            # Enforce CPU-only execution as mandated by audit constraints
            self.device = torch.device("cpu")

        logger.info(f"LocalModelManager initializing on device: {self.device}")

        # Shared Tokenizers (GraphCodeBERT and CodeT5)
        self.gcb_tokenizer = None
        self.codet5_tokenizer = None
        self.tokenizer = None  # Backward-compatibility alias
        self._init_tokenizer()

        # Model caches
        self.p1_models: Dict[str, Any] = {}
        self.p2_model = None
        self.p3_models: Dict[str, Any] = {}

    def _init_tokenizer(self):
        """Initialize GraphCodeBERT and CodeT5 tokenizers."""
        try:
            if PRETRAINED_DIR.is_dir():
                self.gcb_tokenizer = AutoTokenizer.from_pretrained(str(PRETRAINED_DIR))
            else:
                self.gcb_tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
            logger.info("GraphCodeBERT tokenizer loaded successfully.")
        except Exception as e:
            logger.warning(f"Could not load local GCB tokenizer, falling back to HF: {e}")
            self.gcb_tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")

        try:
            if CODET5_DIR.is_dir():
                self.codet5_tokenizer = AutoTokenizer.from_pretrained(str(CODET5_DIR))
            else:
                self.codet5_tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5-base")
            logger.info("CodeT5 tokenizer loaded successfully.")
        except Exception as e:
            logger.warning(f"Could not load CodeT5 tokenizer, falling back to GCB: {e}")
            self.codet5_tokenizer = self.gcb_tokenizer

        # Set default alias
        self.tokenizer = self.gcb_tokenizer

    def get_tokenizer_for_model(self, model: Optional[torch.nn.Module] = None) -> Any:
        """Returns the appropriate tokenizer matching the model's underlying backbone."""
        if self.tokenizer is None:
            return None
        if model is not None and getattr(model, "_securax_backbone", "graphcodebert") == "codet5":
            return self.codet5_tokenizer
        return self.gcb_tokenizer

    def _get_phase1_model(self, tier: str) -> Optional[torch.nn.Module]:
        """Lazy-load Phase 1 binary detection model for specified tier (GraphCodeBERT or CodeT5)."""
        if tier in self.p1_models:
            return self.p1_models[tier]

        # Candidate checkpoint folders
        candidates = [
            MODELS_DIR / f"phase1_winner_{tier}",
            MODELS_DIR / f"phase1_{tier}_codet5",
            MODELS_DIR / f"phase1_{tier}_graphcodebert",
            MODELS_DIR / "phase1_winner_tier1_c_cpp",
        ]

        checkpoint_path = None
        for cand in candidates:
            if (cand / "adapter_model.safetensors").is_file():
                checkpoint_path = cand
                break

        if not checkpoint_path:
            logger.warning(f"No checkpoint found for Phase 1 ({tier})")
            return None

        backbone = _detect_backbone(checkpoint_path)
        try:
            from peft import PeftModel
            if backbone == "codet5":
                from src.models.train_binary_v2 import CodeT5BinaryV2
                codet5_path = CODET5_DIR if CODET5_DIR.is_dir() else "Salesforce/codet5-base"
                base = CodeT5BinaryV2(str(codet5_path))
            else:
                from src.models.train_binary_v2 import GraphCodeBERTV2
                gcb_path = PRETRAINED_DIR if PRETRAINED_DIR.is_dir() else "microsoft/graphcodebert-base"
                base = GraphCodeBERTV2(str(gcb_path))

            model = PeftModel.from_pretrained(base, str(checkpoint_path))
            model._securax_backbone = backbone
            model._securax_tier = tier
            model.to(self.device)
            model.eval()
            self.p1_models[tier] = model
            logger.info(f"Loaded Phase 1 model ({backbone}) for {tier} from {checkpoint_path.name}")
            return model
        except Exception as e:
            logger.error(f"Error loading Phase 1 model for {tier}: {e}")
            return None

    def _get_phase2_model(self, tier: Optional[str] = None) -> Optional[torch.nn.Module]:
        """Lazy-load Phase 2 15-class CWE classifier for specified tier, or shared best."""
        if self.p2_model is not None:
            return self.p2_model

        candidates = []
        if tier:
            candidates.extend([
                MODELS_DIR / f"phase2_winner_{tier}",
                MODELS_DIR / f"phase2_{tier}_graphcodebert",
                MODELS_DIR / f"phase2_{tier}_codet5",
            ])
        candidates.extend([
            MODELS_DIR / "tier1_c_cpp_graphcodebert_cwe_v2_best",
            MODELS_DIR / "tier1_c_cpp_codet5_cwe_debug_best",
            MODELS_DIR / "phase2_winner_tier1_c_cpp",
        ])

        checkpoint_path = None
        for cand in candidates:
            if (cand / "adapter_model.safetensors").is_file():
                checkpoint_path = cand
                break

        if not checkpoint_path:
            logger.warning(f"No checkpoint found for Phase 2 CWE model (tier: {tier})")
            return None

        backbone = _detect_backbone(checkpoint_path)
        try:
            from peft import PeftModel
            if backbone == "codet5":
                from src.models.train_cwe import CodeT5CWEClassifier
                codet5_path = CODET5_DIR if CODET5_DIR.is_dir() else "Salesforce/codet5-base"
                base = CodeT5CWEClassifier(str(codet5_path), num_classes=15)
            else:
                from src.models.train_cwe import GraphCodeBERTCWEClassifier
                base = GraphCodeBERTCWEClassifier(num_classes=15)

            model = PeftModel.from_pretrained(base, str(checkpoint_path))
            model._securax_backbone = backbone
            model.to(self.device)
            model.eval()
            self.p2_model = model
            logger.info(f"Loaded Phase 2 CWE model ({backbone}) from {checkpoint_path.name}")
            return model
        except Exception as e:
            logger.error(f"Error loading Phase 2 CWE model: {e}")
            return None

    def _get_phase3_model(self, tier: str) -> Optional[torch.nn.Module]:
        """Lazy-load Phase 3 CVSS severity regression model for specified tier."""
        if tier in self.p3_models:
            return self.p3_models[tier]

        candidates = [
            MODELS_DIR / f"phase3_A_{tier}_graphcodebert",
            MODELS_DIR / f"phase3_A_{tier}_codet5",
            MODELS_DIR / "phase3_A_tier1_c_cpp_graphcodebert",
            MODELS_DIR / "phase3_A_tier1_c_cpp_codet5",
            MODELS_DIR / "phase3_A_tier2_python_graphcodebert",
        ]

        checkpoint_path = None
        for cand in candidates:
            if (cand / "adapter_model.safetensors").is_file():
                checkpoint_path = cand
                break

        if not checkpoint_path:
            logger.warning(f"No checkpoint found for Phase 3 Severity ({tier})")
            return None

        backbone = _detect_backbone(checkpoint_path)
        try:
            from peft import PeftModel
            if backbone == "codet5":
                from src.models.train_severity import CodeT5SeverityModel
                codet5_path = CODET5_DIR if CODET5_DIR.is_dir() else "Salesforce/codet5-base"
                base = CodeT5SeverityModel(str(codet5_path))
            else:
                from src.models.train_severity import GraphCodeBERTSeverityModel
                gcb_path = PRETRAINED_DIR if PRETRAINED_DIR.is_dir() else "microsoft/graphcodebert-base"
                base = GraphCodeBERTSeverityModel(str(gcb_path))

            model = PeftModel.from_pretrained(base, str(checkpoint_path))
            model._securax_backbone = backbone
            model.to(self.device)
            model.eval()
            self.p3_models[tier] = model
            logger.info(f"Loaded Phase 3 Severity model ({backbone}) for {tier} from {checkpoint_path.name}")
            return model
        except Exception as e:
            logger.error(f"Error loading Phase 3 Severity model for {tier}: {e}")
            return None

    def predict_binary_vf(
        self,
        code: str,
        tier: str,
        language: Optional[str] = None,
        return_explainability: bool = True,
    ) -> Dict[str, Any]:
        """
        Phase 1: Binary Vulnerability Detection with Attention-based Explainability.
        Evaluates code and applies per-tier decision threshold.
        """
        threshold = PHASE1_THRESHOLDS.get(tier, 0.50)
        model = self._get_phase1_model(tier)
        tok = self.get_tokenizer_for_model(model)

        if model is None or tok is None:
            # Fallback heuristic: check for typical vulnerable primitives and verify defense controls
            from src.refinement.static_security import verify_hard_negative_security_controls, inspect_python_code
            is_defended, defense_rationale = verify_hard_negative_security_controls(code, language or tier)

            lang_str = (language or tier or "").lower()
            if "python" in lang_str or "py" in lang_str:
                ast_issues = inspect_python_code(code)
                has_ast_vuln = len(ast_issues) > 0
            else:
                has_ast_vuln = False

            code_lower = code.lower()
            # Dangerous primitives requiring sink or unescaped parameter
            c_cpp_vuln = any(kw in code_lower for kw in ["strcpy(", "sprintf(", "gets(", "system(", "popen(", "eval("])
            heuristic_vuln = has_ast_vuln or (c_cpp_vuln and not is_defended)

            prob = 0.85 if (heuristic_vuln and not is_defended) else 0.05
            is_vuln = False if is_defended else (prob >= threshold)
            res = {
                "is_vulnerable": is_vuln,
                "prob_vuln": prob,
                "threshold": threshold,
                "state": "LIKELY_SAFE_CONTROLS" if is_defended else ("SAFE" if not is_vuln else "VULNERABLE"),
                "mode": "override_calibrated" if is_defended else "heuristic_fallback",
                "hard_negative_override": is_defended,
                "defense_rationale": defense_rationale,
            }
            if return_explainability:
                from src.pipeline.explainability import compute_line_attributions
                res["explainability"] = compute_line_attributions(code, tok, torch.tensor([]))
            return res

        # Prefix language token for Tier 3 shared models (<LANG=xx>)
        input_code = code
        if tier == "tier3_shared" and language:
            input_code = f"<LANG={language.lower()}> {code}"

        try:
            enc = tok(input_code, return_tensors="pt", max_length=512, truncation=True)
            input_ids = enc["input_ids"].to(self.device)
            attention_mask = enc["attention_mask"].to(self.device)

            with torch.no_grad():
                out = model(input_ids=input_ids, attention_mask=attention_mask, return_attention=return_explainability)
                probs = torch.softmax(out.logits, dim=-1)
                prob_vuln = float(probs[0, 1].item())

            # Independent security check for hard negatives (defensive controls)
            from src.refinement.static_security import verify_hard_negative_security_controls
            is_defended, defense_rationale = verify_hard_negative_security_controls(code, language or tier)

            if is_defended:
                is_vuln = False
                state = "LIKELY_SAFE_CONTROLS"
                mode = "override_calibrated"
            elif prob_vuln >= threshold:
                is_vuln = True
                state = "VULNERABLE"
                mode = "neural"
            else:
                is_vuln = False
                state = "SAFE"
                mode = "neural"

            result = {
                "is_vulnerable": is_vuln,
                "prob_vuln": round(prob_vuln, 4),
                "threshold": threshold,
                "state": state,
                "mode": mode,
                "hard_negative_override": is_defended,
                "defense_rationale": defense_rationale,
            }

            if return_explainability and getattr(out, "attention_weights", None) is not None:
                from src.pipeline.explainability import compute_line_attributions
                result["explainability"] = compute_line_attributions(
                    code=code,
                    tokenizer=tok,
                    attention_weights=out.attention_weights[0],
                )

            return result
        except Exception as e:
            logger.error(f"Inference error in Phase 1: {e}")
            res = {
                "is_vulnerable": False,
                "prob_vuln": 0.0,
                "threshold": threshold,
                "mode": "error_fallback",
            }
            if return_explainability:
                from src.pipeline.explainability import compute_line_attributions
                res["explainability"] = compute_line_attributions(code, tok, torch.tensor([]))
            return res

    def predict_cwe(self, code: str, tier: str, language: Optional[str] = None) -> Dict[str, Any]:
        """
        Phase 2: 15-Class CWE Classification with calibrated confidence and evidence resolution.
        Predicts MITRE semantic weakness category and representative CWE ID.
        """
        model = self._get_phase2_model(tier)
        lang_str = language or tier or "Unknown"
        tok = self.get_tokenizer_for_model(model)

        if model is None or tok is None:
            # Evidence-based resolution when neural weights unavailable
            res = resolve_cwe_prediction(
                class_idx=None,
                probabilities=None,
                code=code,
                language=lang_str,
            )
            res["mode"] = "heuristic_fallback"
            return res

        try:
            enc = tok(code, return_tensors="pt", max_length=256, truncation=True)
            input_ids = enc["input_ids"].to(self.device)
            attention_mask = enc["attention_mask"].to(self.device)

            with torch.no_grad():
                out = model(input_ids=input_ids, attention_mask=attention_mask)
                probs = torch.softmax(out.logits, dim=-1)[0]
                class_idx = int(torch.argmax(probs).item())
                probs_list = [float(p.item()) for p in probs]

            res = resolve_cwe_prediction(
                class_idx=class_idx,
                probabilities=probs_list,
                code=code,
                language=lang_str,
                confidence_threshold=0.25,
            )
            res["mode"] = "neural_corroborated" if res["status"] == "corroborated" else ("neural" if res["is_confident"] else "neural_uncertain")
            return res
        except Exception as e:
            logger.error(f"Inference error in Phase 2: {e}")
            res = resolve_cwe_prediction(
                class_idx=None,
                probabilities=None,
                code=code,
                language=lang_str,
            )
            res["mode"] = "error_fallback"
            return res

    def predict_severity(
        self,
        code: str,
        tier: str,
        cwe_id: Optional[str] = None,
        semantic_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Phase 3: CVSS Severity Scoring (0.0 to 10.0 continuous estimate).
        Predicts continuous severity with band mapping, CWE baseline calibration, and uncertainty flags.
        """
        model = self._get_phase3_model(tier)
        tok = self.get_tokenizer_for_model(model)

        # Baseline CWE anchor if known
        clean_cwe = cwe_id.split()[0].strip().upper() if cwe_id and cwe_id.split() else ""
        if clean_cwe in ("N/A", "NONE", "SAFE") or semantic_group == "Safe":
            return {
                "severity_score": None,
                "band": "None",
                "display": "N/A",
                "mode": "safe_baseline",
                "model": "none",
                "is_estimate": False,
                "notice": "Code confirmed safe; severity scoring not applicable.",
            }

        cwe_anchor = CWE_SEVERITY_BENCHMARK.get(clean_cwe) or GROUP_SEVERITY_BENCHMARK.get(semantic_group)

        if model is None or tok is None:
            # Baseline benchmark or heuristic estimate
            code_lower = code.lower()
            if cwe_anchor is not None:
                score = cwe_anchor
            elif any(kw in code_lower for kw in ["strcpy", "system(", "exec(", "eval("]):
                score = 8.5
            else:
                score = 5.5
            band = get_cvss_band(score)
            return {
                "severity_score": round(score, 1),
                "band": band,
                "display": f"{score:.1f} ({band})",
                "mode": "calibrated_baseline",
                "model": "cwe_benchmark_baseline",
                "is_estimate": True,
                "notice": "Estimated severity based on CWE risk category; not an official CVSS assessment.",
            }

        try:
            enc = tok(code, return_tensors="pt", max_length=512, truncation=True)
            input_ids = enc["input_ids"].to(self.device)
            attention_mask = enc["attention_mask"].to(self.device)

            with torch.no_grad():
                out = model(input_ids=input_ids, attention_mask=attention_mask)
                neural_score = float(torch.clamp(out.severity * 10.0, 0.0, 10.0).item())

            # If CWE anchor is available, calibrate the neural prediction to prevent mean-collapse
            if cwe_anchor is not None:
                # Blend 65% CWE baseline + 35% continuous neural score
                score = 0.65 * cwe_anchor + 0.35 * neural_score
                mode = "calibrated_neural"
            else:
                score = neural_score
                mode = "neural"

            score = max(0.0, min(10.0, score))
            band = get_cvss_band(score)
            backbone = getattr(model, "_securax_backbone", "graphcodebert")
            return {
                "severity_score": round(score, 1),
                "band": band,
                "display": f"{score:.1f} ({band})",
                "mode": mode,
                "model": f"phase3_A_{tier}_{backbone}",
                "is_estimate": True,
                "notice": "ML regression estimate calibrated by CWE risk vector; not an official CVSS assessment.",
            }
        except Exception as e:
            logger.error(f"Inference error in Phase 3: {e}")
            score = cwe_anchor if cwe_anchor is not None else 7.5
            band = get_cvss_band(score)
            return {
                "severity_score": round(score, 1),
                "band": band,
                "display": f"{score:.1f} ({band})",
                "mode": "error_fallback",
                "model": "fallback",
                "is_estimate": True,
                "notice": "ML regression estimate; not an official CVSS assessment.",
            }

