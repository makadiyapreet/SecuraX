"""
securax_pipeline.py — Phase 5: Language-Routed End-to-End Analysis Pipeline.

Integrates:
  1. Language Detection & Tier Routing (Pygments + Extension override)
  2. Function Chunker (AST & brace parsers)
  3. Phase 1: Binary Vulnerability Detection (Per-tier threshold)
  4. Phase 2: 15-Class MITRE CWE Classification
  5. Phase 3: Continuous CVSS Severity Scoring
  6. Phase 4: Groq LLM Code Refinement (with cap protection, multi-key failover & disk cache)

Produces output table exactly matching:
  PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
"""

import time
import logging
from typing import Dict, Any, Optional, List

from src.pipeline.language_detector import detect_language, get_supported_languages
from src.pipeline.chunker import split_code_into_functions, count_loc
from src.pipeline.model_manager import LocalModelManager
from src.refinement.groq_client import GroqRefinementClient
from src.refinement.prompts import build_refinement_prompt, parse_refinement_response
from src.refinement.self_verification import self_verify_refinement

logger = logging.getLogger("securax_pipeline")


class SecuraXPipeline:
    """End-to-end multi-tier vulnerability detection, classification, and refinement pipeline."""

    def __init__(self, device: Optional[str] = None):
        self.model_manager = LocalModelManager(device=device)
        self.groq_client = GroqRefinementClient()

    def analyze_source(
        self,
        code: str,
        filename: Optional[str] = None,
        language_override: Optional[str] = None,
        refinement_cap: int = 20,
        enable_self_verification: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute end-to-end analysis on source code.

        Returns structured result dict:
          {
            "success": bool,
            "error": Optional[str],
            "language": str,
            "tier": Optional[str],
            "total_functions": int,
            "vulnerable_count": int,
            "safe_count": int,
            "refined_count": int,
            "cap_hit": bool,
            "refinement_cap": int,
            "rows": List[Dict[str, Any]],  # PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
            "details": List[Dict[str, Any]], # Full snippet and patch details
            "elapsed_seconds": float
          }
        """
        start_time = time.time()

        # Edge case: Empty input
        clean_code = (code or "").strip()
        if not clean_code:
            return {
                "success": False,
                "error": "Source code is empty.",
                "language": "Unknown",
                "tier": None,
                "total_functions": 0,
                "vulnerable_count": 0,
                "safe_count": 0,
                "refined_count": 0,
                "cap_hit": False,
                "refinement_cap": refinement_cap,
                "rows": [],
                "details": [],
                "elapsed_seconds": 0.0,
            }

        # Edge case: Binary file detected
        if "\x00" in clean_code[:4096]:
            return {
                "success": False,
                "error": "Binary file detected. SecuraX requires UTF-8 plain source code.",
                "language": "Binary",
                "tier": None,
                "total_functions": 0,
                "vulnerable_count": 0,
                "safe_count": 0,
                "refined_count": 0,
                "cap_hit": False,
                "refinement_cap": refinement_cap,
                "rows": [],
                "details": [],
                "elapsed_seconds": 0.0,
            }

        # Step 1: Language Detection & Tier Routing
        if language_override and language_override != "Auto-Detect":
            from src.pipeline.language_detector import map_language_to_tier
            language = language_override
            tier = map_language_to_tier(language)
            is_supported = tier is not None
            msg = f"User selected {language} -> {tier}" if is_supported else f"Unsupported language: {language}"
        else:
            language, tier, is_supported, msg = detect_language(clean_code, filename=filename)

        if not is_supported or not tier:
            return {
                "success": False,
                "error": msg,
                "language": language,
                "tier": None,
                "total_functions": 0,
                "vulnerable_count": 0,
                "safe_count": 0,
                "refined_count": 0,
                "cap_hit": False,
                "refinement_cap": refinement_cap,
                "rows": [],
                "details": [],
                "elapsed_seconds": time.time() - start_time,
            }

        # Step 2: Split into functions / snippets
        chunks = split_code_into_functions(clean_code, language)
        if not chunks:
            chunks = [{
                "name": "full_code",
                "code": clean_code,
                "start_line": 1,
                "end_line": len(clean_code.splitlines()),
                "loc": count_loc(clean_code),
            }]

        rows: List[Dict[str, Any]] = []
        details: List[Dict[str, Any]] = []

        vulnerable_count = 0
        safe_count = 0
        refined_count = 0
        cap_hit = False

        # Step 3: Sequential Pipeline Analysis per Chunk
        for idx, chunk in enumerate(chunks):
            snippet_name = chunk.get("name", f"function_{idx+1}")
            snippet_code = chunk.get("code", "")
            loc = chunk.get("loc", count_loc(snippet_code))

            # Phase 1: Binary Vulnerability Detection
            p1_res = self.model_manager.predict_binary_vf(
                snippet_code,
                tier=tier,
                language=language,
            )
            is_vulnerable = p1_res.get("is_vulnerable", False)
            prob_vuln = p1_res.get("prob_vuln", 0.0)

            if is_vulnerable:
                vulnerable_count += 1
                vf_label = "Vulnerable"

                # Phase 2: CWE Classification
                p2_res = self.model_manager.predict_cwe(snippet_code, tier, language=language)
                cwe_id = p2_res.get("cwe_id", "CWE-Unknown")
                semantic_group = p2_res.get("semantic_group", "Other-Security")
                vuln_name = p2_res.get("vulnerability_name", "")

                # Format display for CWE-id column: "CWE-89 (SQL Injection)" or "Uncertain (Review Recommended)"
                if cwe_id == "Uncertain":
                    display_cwe = "Uncertain (Review Recommended)"
                elif vuln_name and vuln_name != cwe_id:
                    display_cwe = f"{cwe_id} ({vuln_name})"
                else:
                    display_cwe = cwe_id

                # Phase 3: Severity Scoring
                p3_res = self.model_manager.predict_severity(
                    snippet_code,
                    tier,
                    cwe_id=cwe_id,
                    semantic_group=semantic_group,
                )
                cvss_score = p3_res.get("severity_score", 5.0)
                cvss_band = p3_res.get("band", "Medium")
                severity_str = f"{cvss_score:.1f} / 10.0"

                # Phase 4 / Phase 7 Option B: Code Refinement & Self-Verification
                sv_res = None
                if refined_count < refinement_cap:
                    if enable_self_verification:
                        # Phase 7 Option B: Self-Verification Loop
                        sv_res = self_verify_refinement(
                            code=snippet_code,
                            language=language,
                            tier=tier,
                            cwe_id=cwe_id,
                            model_manager=self.model_manager,
                            groq_client=self.groq_client,
                            candidate_patch=None,
                            semantic_group=semantic_group,
                            severity_score=cvss_score,
                        )
                        refined_code = sv_res.get("final_code") or "Refinement unavailable"
                        if sv_res.get("success"):
                            refined_count += 1
                    else:
                        # Standard single-pass refinement
                        prompt = build_refinement_prompt(
                            language=language,
                            vulnerable_snippet=snippet_code,
                            cwe_id=cwe_id,
                            semantic_group=semantic_group,
                            severity_score=cvss_score,
                            max_snippet_chars=3500,
                        )

                        groq_res = self.groq_client.complete(
                            user_prompt=prompt,
                            model=self.groq_client.model,
                            temperature=0.1,
                            max_tokens=800,
                        )

                        if groq_res.get("status") in ("success", "cached"):
                            parsed = parse_refinement_response(groq_res.get("content"), expected_language=language)
                            refined_code = parsed.get("refined_code") or parsed.get("code") or "Refinement unavailable: empty patch generated"
                            refined_count += 1
                        elif groq_res.get("status") == "refinement_unavailable":
                            reason = groq_res.get("reason") or groq_res.get("error_message") or "API unavailable"
                            refined_code = f"Refinement unavailable: {reason}"
                        else:
                            err_msg = groq_res.get("error_message") or groq_res.get("status") or "Unknown error"
                            refined_code = f"Refinement unavailable: {err_msg}"
                else:
                    cap_hit = True
                    refined_code = f"Refinement cap reached ({refinement_cap}/{refinement_cap}) — on-demand refinement available"

            else:
                sv_res = None
                safe_count += 1
                if p1_res.get("hard_negative_override"):
                    vf_label = "Controls detected - likely safe"
                else:
                    vf_label = "Safe"
                display_cwe = "N/A"
                cwe_id = "N/A"
                semantic_group = "Safe"
                vuln_name = "None"
                severity_str = "N/A"
                refined_code = "N/A"
                cvss_score = None
                cvss_band = None

            # EXACT Output row schema:
            # PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score
            row = {
                "PL": language,
                "Snippet": f"{snippet_name}()",
                "VF": vf_label,
                "CWE-id": display_cwe,
                "Refined Code": refined_code,
                "LOC": loc,
                "Severity Score": severity_str,
            }
            rows.append(row)

            # Detailed record for UI expandable views and diffing
            details.append({
                "index": idx + 1,
                "name": snippet_name,
                "language": language,
                "tier": tier,
                "loc": loc,
                "original_code": snippet_code,
                "is_vulnerable": is_vulnerable,
                "prob_vuln": prob_vuln,
                "neural_prob": round(float(prob_vuln), 4),
                "vf_label": vf_label,
                "override_applied": bool(p1_res.get("hard_negative_override", False)),
                "override_reason": p1_res.get("defense_rationale"),
                "cwe_id": cwe_id,
                "semantic_group": semantic_group,
                "vulnerability_name": vuln_name,
                "cwe_details": p2_res if is_vulnerable else None,
                "severity_score": cvss_score,
                "severity_band": cvss_band,
                "severity_details": p3_res if is_vulnerable else None,
                "refined_code": refined_code,
                "can_refine_on_demand": is_vulnerable and ("Refinement cap reached" in refined_code or "Refinement unavailable" in refined_code),
                "explainability": p1_res.get("explainability"),
                "self_verification": sv_res,
            })

        elapsed = time.time() - start_time

        return {
            "success": True,
            "error": None,
            "language": language,
            "tier": tier,
            "total_functions": len(chunks),
            "vulnerable_count": vulnerable_count,
            "safe_count": safe_count,
            "refined_count": refined_count,
            "cap_hit": cap_hit,
            "refinement_cap": refinement_cap,
            "rows": rows,
            "details": details,
            "elapsed_seconds": round(elapsed, 2),
        }

    def refine_single_snippet_on_demand(
        self,
        snippet_code: str,
        language: str,
        cwe_id: str = "CWE-Unknown",
        semantic_group: Optional[str] = None,
        severity_score: Optional[float] = None,
        tier: Optional[str] = None,
        enable_self_verification: bool = False,
    ) -> Dict[str, Any]:
        """Refine an individual snippet on demand (e.g. if skipped by cap or retried)."""
        if enable_self_verification:
            from src.pipeline.language_detector import map_language_to_tier
            resolved_tier = tier or map_language_to_tier(language) or "tier2_python"
            sv = self_verify_refinement(
                code=snippet_code,
                language=language,
                tier=resolved_tier,
                cwe_id=cwe_id,
                model_manager=self.model_manager,
                groq_client=self.groq_client,
                candidate_patch=None,
                semantic_group=semantic_group,
                severity_score=severity_score,
            )
            return {
                "success": sv.get("success", False),
                "refined_code": sv.get("final_code") or "Refinement unavailable",
                "cached": False,
                "model": self.groq_client.model,
                "self_verification": sv,
            }

        prompt = build_refinement_prompt(
            language=language,
            vulnerable_snippet=snippet_code,
            cwe_id=cwe_id,
            semantic_group=semantic_group,
            severity_score=severity_score,
            max_snippet_chars=3500,
        )

        res = self.groq_client.complete(
            user_prompt=prompt,
            model=self.groq_client.model,
            temperature=0.1,
            max_tokens=800,
        )

        if res.get("status") in ("success", "cached"):
            parsed = parse_refinement_response(res.get("content"), expected_language=language)
            return {
                "success": True,
                "refined_code": parsed.get("refined_code") or parsed.get("code") or "Refinement returned empty block",
                "cached": res.get("cached", False),
                "model": res.get("model", self.groq_client.model),
            }
        else:
            reason = res.get("reason") or res.get("error_message") or "Refinement call failed"
            return {
                "success": False,
                "refined_code": f"Refinement unavailable: {reason}",
                "cached": False,
                "model": self.groq_client.model,
            }
