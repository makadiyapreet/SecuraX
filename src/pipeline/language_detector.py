"""
language_detector.py — Phase 5: Language Detection and Tier Routing.

Identifies programming language and maps to the appropriate SecuraX tier:
  - Uses Pygments `guess_lexer()` as primary signal for raw snippets.
  - File extension as authoritative override when filename is present.
  - Dynamically reads supported languages from data/processed/manifest.json.
  - Fails gracefully for unsupported languages without routing to an invalid tier.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

from pygments.lexers import guess_lexer, get_lexer_for_filename
from pygments.util import ClassNotFound

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = PROJECT_ROOT / "data" / "processed" / "manifest.json"

logger = logging.getLogger("language_detector")

# Comprehensive extension to language mapping
EXTENSION_MAP = {
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hxx": "C++",
    ".py": "Python",
    ".pyw": "Python",
    ".php": "PHP",
    ".phtml": "PHP",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rb": "Ruby",
    ".json": "JSON",
    # Unsupported extensions (explicitly classified)
    ".cs": "C#",
    ".css": "CSS",
    ".html": "HTML",
    ".htm": "HTML",
    ".kt": "Kotlin",
    ".lua": "Lua",
    ".md": "Markdown",
    ".m": "Objective-C",
    ".pl": "Perl",
    ".rs": "Rust",
    ".sql": "SQL",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".swift": "Swift",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
}

# Normalization mapping for Pygments lexer names / aliases to canonical names
PYGMENTS_NAME_MAP = {
    "c": "C",
    "c++": "C++",
    "cpp": "C++",
    "python": "Python",
    "python 3": "Python",
    "php": "PHP",
    "go": "Go",
    "golang": "Go",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "ruby": "Ruby",
    "json": "JSON",
    "rust": "Rust",
    "csharp": "C#",
    "c#": "C#",
    "html": "HTML",
    "css": "CSS",
    "kotlin": "Kotlin",
    "swift": "Swift",
    "shell": "Shell",
    "bash": "Shell",
    "sql": "SQL",
    "scala": "Scala",
    "perl": "Perl",
}

# Language-specific quick heuristic signatures for raw snippet disambiguation
HEURISTIC_SIGNATURES = [
    # (regex/check, canonical language)
    ("<?php", "PHP"),
    ("#include <", "C"),
    ("#include \"", "C"),
    ("std::", "C++"),
    ("cout <<", "C++"),
    ("cin >>", "C++"),
    ("namespace ", "C++"),
    ("def ", "Python"),
    ("import ", "Python"),
    ("from ", "Python"),
    ("package main", "Go"),
    ("func ", "Go"),
    ("public class ", "Java"),
    ("System.out.println", "Java"),
    ("console.log", "JavaScript"),
    ("const ", "JavaScript"),
    ("let ", "JavaScript"),
]


def load_manifest_tiers() -> Dict[str, Any]:
    """Load tier assignments and supported languages from manifest.json."""
    if not MANIFEST_PATH.is_file():
        # Fallback default tier definitions if manifest is missing
        return {
            "tier_assignments": {
                "tier1": ["C"],
                "tier2": ["C++", "PHP", "Python"],
                "tier3": ["Go", "JSON", "Java", "JavaScript", "Other", "Ruby", "TypeScript"],
                "excluded": ["C#", "CSS", "HTML", "Kotlin", "Lua", "Markdown", "Objective-C", "Perl", "Rust", "SQL", "Scala", "Shell", "Swift", "Unknown", "XML", "YAML"],
            }
        }
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_supported_languages() -> List[str]:
    """Return sorted list of supported languages having trained models."""
    manifest = load_manifest_tiers()
    tiers = manifest.get("tier_assignments", {})
    supported = []
    for t in ["tier1", "tier2", "tier3"]:
        supported.extend(tiers.get(t, []))
    # Deduplicate and sort, excluding generic 'Other'
    return sorted(list({lang for lang in supported if lang != "Other"}))


LANGUAGE_ALIASES = {
    "c": "C",
    "cpp": "C++",
    "c++": "C++",
    "cplusplus": "C++",
    "python": "Python",
    "py": "Python",
    "python3": "Python",
    "php": "PHP",
    "php3": "PHP",
    "php4": "PHP",
    "php5": "PHP",
    "php7": "PHP",
    "go": "Go",
    "golang": "Go",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "node": "JavaScript",
    "nodejs": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "ruby": "Ruby",
    "rb": "Ruby",
    "json": "JSON",
}


def canonicalize_language(language: Optional[str]) -> str:
    """Normalize language string to canonical title-cased SecuraX name."""
    if not language:
        return "Unknown"
    cleaned = language.strip()
    return LANGUAGE_ALIASES.get(cleaned.lower(), cleaned)


def map_language_to_tier(language: str) -> Optional[str]:
    """
    Map canonical language name to SecuraX model tier identifier.
    Returns None if language is unsupported or lacks a trained model tier.
    """
    lang_clean = canonicalize_language(language)
    manifest = load_manifest_tiers()
    tiers = manifest.get("tier_assignments", {})

    # Tier 1
    if lang_clean in tiers.get("tier1", ["C"]) or lang_clean == "C":
        return "tier1_c_cpp"

    # Tier 2 (per-language models)
    if lang_clean == "C++":
        return "tier2_cpp"
    if lang_clean == "PHP":
        return "tier2_php"
    if lang_clean == "Python":
        return "tier2_python"

    # Tier 3 (shared model across Go, Java, JS, Ruby, TS, etc.)
    tier3_langs = tiers.get("tier3", ["Go", "Java", "JavaScript", "Ruby", "TypeScript", "JSON", "Other"])
    if lang_clean in tier3_langs:
        return "tier3_shared"

    # Not supported
    return None


def detect_language(code: str, filename: Optional[str] = None) -> Tuple[str, Optional[str], bool, str]:
    """
    Detect programming language and resolve tier.

    Returns:
        (language_name, tier_name, is_supported, message)
    """
    code_clean = (code or "").strip()
    detected_lang: Optional[str] = None

    # Step 1: File extension override when filename is provided
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in EXTENSION_MAP:
            detected_lang = EXTENSION_MAP[ext]
            logger.debug(f"Detected language '{detected_lang}' from extension '{ext}'")

    # Step 2: Disambiguation heuristics for common raw snippets
    if not detected_lang and code_clean:
        for sig, lang in HEURISTIC_SIGNATURES:
            if sig in code_clean:
                detected_lang = lang
                logger.debug(f"Detected language '{detected_lang}' via heuristic '{sig}'")
                break

    # Step 3: Pygments guess_lexer as primary signal for raw code
    if not detected_lang and code_clean:
        try:
            lexer = guess_lexer(code_clean)
            for alias in [lexer.name.lower()] + lexer.aliases:
                if alias in PYGMENTS_NAME_MAP:
                    detected_lang = PYGMENTS_NAME_MAP[alias]
                    break
            if not detected_lang:
                detected_lang = lexer.name
        except (ClassNotFound, Exception) as e:
            logger.debug(f"Pygments could not guess lexer: {e}")

    # Fallback to C if still unknown but looks like C-family code
    if not detected_lang:
        if "{" in code_clean and "}" in code_clean and ";" in code_clean:
            detected_lang = "C"
        else:
            detected_lang = "Unknown"

    # Resolve tier
    tier = map_language_to_tier(detected_lang)
    supported_langs = get_supported_languages()

    if tier is not None:
        return detected_lang, tier, True, f"Routed to {tier} ({detected_lang})"
    else:
        err_msg = (
            f"Language '{detected_lang}' is not supported. "
            f"SecuraX trained tiers support: {', '.join(supported_langs)}."
        )
        return detected_lang, None, False, err_msg

