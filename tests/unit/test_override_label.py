"""
tests/unit/test_override_label.py — Unit tests for Neuro-Symbolic Override Relabeling.

Ensures:
  1. Defended hard negatives return VF == "Controls detected - likely safe" (enum LIKELY_SAFE_CONTROLS).
  2. Inherently clean code returns plain "Safe".
  3. override_applied, override_reason, and neural_prob are preserved honestly.
"""

import pytest
from src.pipeline.securax_pipeline import SecuraXPipeline


@pytest.fixture(scope="module")
def pipeline():
    return SecuraXPipeline()


def test_defended_php_file_upload_override(pipeline):
    """PHP Secure File Upload with strict whitelist and mime checking."""
    code = """<?php
function uploadProfilePicture($file) {
    $allowed = ["jpg", "jpeg", "png"];
    $ext = pathinfo($file["name"], PATHINFO_EXTENSION);
    if (in_array(strtolower($ext), $allowed, true)) {
        if (mime_content_type($file["tmp_name"]) === "image/jpeg") {
            $dest = "uploads/" . uniqid("avatar_") . "." . $ext;
            move_uploaded_file($file["tmp_name"], $dest);
            return true;
        }
    }
    return false;
}
?>"""
    res = pipeline.analyze_source(code, filename="upload.php")
    assert res["success"] is True
    assert len(res["rows"]) >= 1
    row = res["rows"][0]
    detail = res["details"][0]

    assert row["VF"] == "Controls detected - likely safe"
    assert detail["override_applied"] is True
    assert detail["override_reason"] is not None
    assert "whitelist" in detail["override_reason"].lower() or "extension" in detail["override_reason"].lower()


def test_clean_safe_code_returns_plain_safe(pipeline):
    """Clean utility function has no security controls and is plain Safe."""
    code = """int add_numbers(int a, int b) {
    return a + b;
}"""
    res = pipeline.analyze_source(code, filename="math.c")
    assert res["success"] is True
    assert len(res["rows"]) >= 1
    row = res["rows"][0]
    detail = res["details"][0]

    assert row["VF"] == "Safe"
    assert detail["override_applied"] is False


def test_vulnerable_code_is_not_overridden(pipeline):
    """Vulnerable SQL injection without controls must remain Vulnerable."""
    code = """import sqlite3
def search_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()
"""
    res = pipeline.analyze_source(code, filename="search.py")
    assert res["success"] is True
    row = res["rows"][0]
    detail = res["details"][0]

    assert row["VF"] == "Vulnerable"
    assert detail["override_applied"] is False
