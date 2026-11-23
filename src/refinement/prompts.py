"""
prompts.py — Phase 4: Refinement Prompt Templates & Response Parsing.

Implements:
  - SYSTEM_PROMPT: Strict security repair specialist instructions
  - Language-specific and CWE-specific guidance generator
  - build_refinement_prompt: Formats prompt with PL, CWE, semantic group, severity, and code
  - parse_refinement_response: Robust multi-case parser handling fences, truncation, and raw text
"""

import re
from typing import Dict, Any, Optional, List, Tuple

SYSTEM_PROMPT = (
    "You are an expert security engineer and automated software vulnerability repair specialist. "
    "Your objective is to repair vulnerable source code functions. "
    "Given a vulnerable function, its CWE classification, and its vulnerability details, "
    "you must produce a safe, robust, minimal patch that eliminates the vulnerability "
    "while strictly preserving the exact function signature, return type, and intended operational behavior. "
    "Output ONLY the complete corrected function in a single markdown code block. "
    "Do NOT output markdown commentary, explanations, reasoning, or text outside the code block."
)

# Language-specific & CWE-specific security hints
HINT_RULES: List[Tuple[re.Pattern, str, str]] = [
    # (cwe_regex, language_regex, hint)
    (re.compile(r"CWE-(89|564)", re.I), r"python", "Use parameterized queries or ORM placeholders; never format or concatenate untrusted input into SQL statements."),
    (re.compile(r"CWE-(89|564)", re.I), r"php", "Use PDO or MySQLi prepared statements with bound parameters ($stmt->bind_param); avoid string interpolation."),
    (re.compile(r"CWE-(89|564)", re.I), r".*", "Use parameterized queries or prepared statements; isolate query structure from untrusted input."),
    (re.compile(r"CWE-(79|80)", re.I), r"php", "Sanitize and escape output with htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')."),
    (re.compile(r"CWE-(79|80)", re.I), r"javascript|typescript|js|ts", "Encode untrusted data before DOM insertion; use textContent or safe DOM sanitization libraries."),
    (re.compile(r"CWE-(78|88)", re.I), r"python", "Use subprocess.run with an argument list and shell=False; avoid passing raw strings with shell=True."),
    (re.compile(r"CWE-(78|88)", re.I), r".*", "Avoid executing shell commands with unsanitized arguments; validate inputs against an explicit allowlist."),
    (re.compile(r"CWE-(22|23|36|73)", re.I), r"python", "Use os.path.abspath / Path.resolve() and verify the target path strictly starts with the authorized base directory."),
    (re.compile(r"CWE-(22|23|36|73)", re.I), r".*", "Validate canonical file paths against an approved base directory; reject paths containing '..' or path separators."),
    (re.compile(r"CWE-(119|120|121|122|787)", re.I), r"c|c\+\+|cpp", "Enforce strict buffer bounds checking before write operations; use safe bounded functions (e.g. snprintf, strlcpy) or dynamic containers."),
    (re.compile(r"CWE-125", re.I), r"c|c\+\+|cpp", "Verify that buffer index and length offsets are non-negative and strictly less than total allocated buffer size before reading."),
    (re.compile(r"CWE-(416|415)", re.I), r"c|c\+\+|cpp", "Ensure pointers are set to NULL immediately after free(); prevent double deallocation and dangling pointer dereference."),
    (re.compile(r"CWE-476", re.I), r"c|c\+\+|cpp", "Check pointers for NULL before dereferencing, particularly following memory allocation, search, or lookup functions."),
    (re.compile(r"CWE-190", re.I), r"c|c\+\+|cpp", "Check for integer overflow / wraparound before arithmetic operations, memory allocation size computations, or loop bounds."),
    (re.compile(r"CWE-(287|306|285|862)", re.I), r".*", "Enforce authentication and role-based authorization checks before granting access to sensitive functions or data."),
    (re.compile(r"CWE-(327|328|330)", re.I), r".*", "Use cryptographically secure standard libraries (e.g. secrets, OpenSSL) rather than broken primitives (e.g. MD5, DES, standard rand())."),
]

DEFAULT_HINTS = {
    "Buffer-Overflow": "Enforce strict buffer boundary checks prior to writing. Replace unsafe functions with length-bounded variants.",
    "OOB-Read": "Ensure indices are checked against allocated boundary bounds before accessing memory.",
    "OOB-Write": "Check destination bounds and enforce limits on input size before copying.",
    "Use-After-Free": "Clear or nullify pointers upon deallocation to avoid stale pointer dereferences.",
    "Double-Free": "Avoid freeing the same memory address multiple times; set pointer to NULL after free.",
    "NULL-Deref": "Perform explicit NULL verification prior to pointer access.",
    "Integer-Issues": "Guard against integer overflow or truncation prior to memory allocation or arithmetic.",
    "Input-Validation": "Validate input length, type, and format against a strict allowlist before processing.",
    "Info-Exposure": "Prevent logging or leaking sensitive internal state, credentials, or uninitialized memory.",
    "Access-Control": "Verify identity and appropriate permissions prior to privileged operations.",
    "Crypto-Issues": "Replace insecure cryptographic algorithms or weak random number generators with modern standards.",
    "Resource-Mgmt": "Ensure all acquired resources (handles, memory, files, locks) are safely released under all exit paths.",
    "Race-Condition": "Use appropriate mutual exclusion locks or atomic operations to synchronize shared state.",
    "Path-Traversal": "Canonicalize paths and verify they reside within the intended base directory.",
    "Other-Security": "Apply canonical secure coding best practices for this weakness category.",
}


def get_language_hint(language: str, cwe_id: str, semantic_group: Optional[str] = None) -> str:
    """Return tailored security hint based on language, CWE, and semantic category."""
    lang_clean = (language or "").strip().lower()
    cwe_clean = (cwe_id or "").strip().upper()

    for cwe_pattern, lang_pattern, hint in HINT_RULES:
        if cwe_pattern.search(cwe_clean) and re.match(lang_pattern, lang_clean, re.I):
            return hint

    # Fallback to semantic group hint if available
    if semantic_group and semantic_group in DEFAULT_HINTS:
        return DEFAULT_HINTS[semantic_group]

    return "Apply the minimal, canonical secure coding practice for this weakness while keeping behavior intact."


def build_refinement_prompt(
    language: str,
    vulnerable_snippet: str,
    cwe_id: str,
    semantic_group: Optional[str] = None,
    cwe_description: Optional[str] = None,
    severity_score: Optional[float] = None,
    vulnerable_lines: Optional[str] = None,
    max_snippet_chars: int = 3500,
) -> str:
    """
    Build structured, context-rich prompt for Groq LLM refinement.
    Ensures snippet length stays well under free-tier token ceilings.
    """
    lang_display = language.capitalize() if language else "Code"
    cwe_desc_str = f" - {cwe_description}" if cwe_description else ""
    cwe_group_str = f" ({semantic_group})" if semantic_group else ""
    severity_str = f"{severity_score:.1f} / 10.0 (CVSS)" if severity_score is not None else "Not specified"

    hint = get_language_hint(language, cwe_id, semantic_group)

    vuln_lines_section = ""
    if vulnerable_lines:
        vuln_lines_section = f"- Potentially Vulnerable Region/Lines: {vulnerable_lines}\n"

    # Truncate snippet if oversized to prevent HTTP 413 / ITPM rate limit errors
    clean_code = (vulnerable_snippet or "").strip()
    if len(clean_code) > max_snippet_chars:
        clean_code = clean_code[:max_snippet_chars] + f"\n\n// ... [Code truncated at {max_snippet_chars} chars to fit context window] ..."

    prompt = f"""Fix the following vulnerable {lang_display} function.

Vulnerability Context:
- Programming Language: {lang_display}
- Weakness: {cwe_id}{cwe_desc_str}{cwe_group_str}
- Estimated Severity: {severity_str}
{vuln_lines_section}- Security Recommendation: {hint}

Vulnerable Code:
```{lang_display.lower()}
{clean_code}
```

Instructions:
1. Return ONLY the complete repaired function in a single markdown code block (```{lang_display.lower()} ... ```).
2. Retain the exact function signature, parameters, and return types.
3. Apply the minimal necessary patch to eliminate the weakness while preserving full intended functional behavior.
4. Do NOT output any conversational text, analysis, markdown commentary, or explanations outside the code block.
"""
    return prompt


def parse_refinement_response(
    raw_response: Optional[str],
    expected_language: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Extract refined code from LLM response.
    
    Handles:
      - None / empty string
      - Standard single fenced code block
      - Multiple fenced code blocks (extracts main function block)
      - Unclosed fence / truncated output
      - Raw code returned without markdown fences
      
    Returns:
      {
        "refined_code": str or None,
        "raw_response": str or None,
        "status": "success" | "multiple_blocks" | "truncated" | "raw_code_no_fences" | "empty_output" | "no_code_block",
        "warning": str or None
      }
    """
    if not raw_response or not raw_response.strip():
        return {
            "refined_code": None,
            "raw_response": raw_response,
            "status": "empty_output",
            "warning": "Model returned an empty response.",
        }

    text = raw_response.strip()

    # Pattern for standard markdown code blocks ```lang ... ```
    fence_pattern = re.compile(r"```(?:[a-zA-Z0-9_\+#\-]+)?\s*\n(.*?)```", re.DOTALL)
    matches = fence_pattern.findall(text)

    if len(matches) == 1:
        code = matches[0].strip()
        if code:
            return {
                "refined_code": code,
                "raw_response": raw_response,
                "status": "success",
                "warning": None,
            }

    elif len(matches) > 1:
        # Multiple code blocks returned. Choose the largest block (usually the full function)
        best_block = max(matches, key=lambda b: len(b.strip()))
        return {
            "refined_code": best_block.strip(),
            "raw_response": raw_response,
            "status": "multiple_blocks",
            "warning": f"Model returned {len(matches)} code blocks; selected the largest block.",
        }

    # Check for unclosed fence (truncated generation)
    unclosed_match = re.search(r"```(?:[a-zA-Z0-9_\+#\-]+)?\s*\n(.*)$", text, re.DOTALL)
    if unclosed_match:
        code = unclosed_match.group(1).strip()
        if code:
            return {
                "refined_code": code,
                "raw_response": raw_response,
                "status": "truncated",
                "warning": "Code block was truncated (unclosed markdown fence).",
            }

    # No markdown fences found: check if the text itself looks like raw code
    lines = [l for l in text.splitlines() if l.strip()]
    code_indicators = ["def ", "function ", "void ", "int ", "char ", "public ", "class ", "return ", "{", "}", "import "]
    has_code_syntax = any(any(ind in line for ind in code_indicators) for line in lines[:10])

    if has_code_syntax:
        # Strip potential markdown bolding or leading quotes
        clean_lines = []
        for line in text.splitlines():
            if line.strip().startswith("```"):
                continue
            clean_lines.append(line)
        cleaned_code = "\n".join(clean_lines).strip()
        if cleaned_code:
            return {
                "refined_code": cleaned_code,
                "raw_response": raw_response,
                "status": "raw_code_no_fences",
                "warning": "No markdown code fence found; parsed raw output as code.",
            }

    return {
        "refined_code": None,
        "raw_response": raw_response,
        "status": "no_code_block",
        "warning": "Failed to extract valid code from model response.",
    }


def build_self_verification_prompt(
    language: str,
    original_code: str,
    previous_patch: str,
    cwe_id: str,
    detector_prob: float,
    detector_threshold: float,
    static_warnings: Optional[List[str]] = None,
    syntax_error: Optional[str] = None,
    explainability_lines: Optional[str] = None,
    max_snippet_chars: int = 3500,
) -> str:
    """
    Build targeted feedback prompt for Phase 7 Option B Self-Verification re-prompting.
    Provides the previous failed patch, Phase 1 binary detector feedback, static analysis findings,
    and instructions to produce a completely fixed function.
    """
    lang_display = language.capitalize() if language else "Code"
    clean_orig = (original_code or "").strip()
    clean_prev = (previous_patch or "").strip()

    if len(clean_orig) > max_snippet_chars:
        clean_orig = clean_orig[:max_snippet_chars] + "\n// ... [truncated] ..."
    if len(clean_prev) > max_snippet_chars:
        clean_prev = clean_prev[:max_snippet_chars] + "\n// ... [truncated] ..."

    # Construct verification failure details
    issues_items = []
    if syntax_error:
        issues_items.append(f"- Syntax Validation Error: {syntax_error}")

    issues_items.append(
        f"- Residual Vulnerability Detected: The SecuraX neural detector evaluated your patch and flagged it as "
        f"STILL VULNERABLE with probability {detector_prob:.1%} (Safety threshold is {detector_threshold:.2f})."
    )

    if explainability_lines:
        issues_items.append(f"- Suspicious Lines in Patch: {explainability_lines}")

    if static_warnings:
        for w in static_warnings[:5]:  # limit to top 5 warnings
            issues_items.append(f"- Static Analysis Warning: {w}")

    issues_text = "\n".join(issues_items)

    prompt = f"""Your previous attempt to fix a vulnerable {lang_display} function failed automated verification.

Target Weakness: {cwe_id}

Automated Verification Feedback:
{issues_text}

Original Vulnerable Function:
```{lang_display.lower()}
{clean_orig}
```

Your Previous Patch Candidate (Failed Verification):
```{lang_display.lower()}
{clean_prev}
```

Corrective Instructions:
1. Carefully analyze the residual vulnerability and static analysis findings reported above.
2. Rewrite the function from scratch to address the root cause and ensure it is 100% secure.
3. Retain the exact function signature, return type, and intended operational logic.
4. Output ONLY the repaired function in a single markdown code block (```{lang_display.lower()} ... ```).
5. Do NOT include markdown commentary or explanations outside the code block.
"""
    return prompt


