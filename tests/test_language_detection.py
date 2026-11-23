"""
test_language_detection.py — Unit & Regression Tests for Language Detection & Routing.

Tests:
  - Extension-based resolution.
  - Pygments guess_lexer() detection on raw snippets.
  - Multi-tier routing (tier1_c_cpp, tier2_cpp, tier2_python, tier2_php, tier3_shared).
  - Unsupported language handling (Rust, Shell, SQL, etc.).
"""

import pytest
from src.pipeline.language_detector import (
    detect_language,
    map_language_to_tier,
    get_supported_languages,
    EXTENSION_MAP,
)


def test_extension_detection():
    """Verify that file extension overrides raw content correctly."""
    lang, tier, supported, msg = detect_language("int x = 1;", filename="test.py")
    assert lang == "Python"
    assert tier == "tier2_python"
    assert supported is True

    lang, tier, supported, msg = detect_language("print('hello')", filename="app.c")
    assert lang == "C"
    assert tier == "tier1_c_cpp"
    assert supported is True

    lang, tier, supported, msg = detect_language("function f() {}", filename="script.php")
    assert lang == "PHP"
    assert tier == "tier2_php"
    assert supported is True


def test_tier_mappings():
    """Verify all supported languages map to the expected SecuraX tiers."""
    assert map_language_to_tier("C") == "tier1_c_cpp"
    assert map_language_to_tier("C++") == "tier2_cpp"
    assert map_language_to_tier("Python") == "tier2_python"
    assert map_language_to_tier("PHP") == "tier2_php"
    assert map_language_to_tier("Go") == "tier3_shared"
    assert map_language_to_tier("Java") == "tier3_shared"
    assert map_language_to_tier("JavaScript") == "tier3_shared"
    assert map_language_to_tier("TypeScript") == "tier3_shared"
    assert map_language_to_tier("Ruby") == "tier3_shared"


def test_unsupported_languages():
    """Ensure unsupported languages fail gracefully without assigning invalid tiers."""
    for unsupported in ["Rust", "SQL", "Shell", "Kotlin", "Swift", "C#"]:
        tier = map_language_to_tier(unsupported)
        assert tier is None, f"{unsupported} should have no trained tier"

        lang, resolved_tier, is_supported, msg = detect_language("fn main() {}", filename=f"code.{unsupported.lower()}")
        assert is_supported is False
        assert resolved_tier is None
        assert "not supported" in msg


def test_raw_snippet_heuristics():
    """Verify raw code detection without filename."""
    php_code = "<?php echo 'hello'; ?>"
    lang, tier, supported, _ = detect_language(php_code)
    assert lang == "PHP"
    assert tier == "tier2_php"

    c_code = "#include <stdio.h>\nint main() { return 0; }"
    lang, tier, supported, _ = detect_language(c_code)
    assert lang == "C"
    assert tier == "tier1_c_cpp"

    py_code = "import os\ndef test(): pass"
    lang, tier, supported, _ = detect_language(py_code)
    assert lang == "Python"
    assert tier == "tier2_python"


def test_supported_languages_list():
    """Verify supported language list contains core project languages."""
    langs = get_supported_languages()
    for req in ["C", "C++", "Python", "PHP", "Go", "Java", "JavaScript", "Ruby", "TypeScript"]:
        assert req in langs

