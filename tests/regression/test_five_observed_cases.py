"""
test_five_observed_cases.py — Mandatory Regression Suite for the 5 Specific Observed Cases.

Covers:
  1. JavaScript Open Redirect (CWE-601)
  2. Python Path Traversal (CWE-22)
  3. C Integer Overflow (CWE-190)
  4. PHP Secure File Upload (Safe / Hard Negative / CWE-434 defended)
  5. Java Insecure Deserialization (CWE-502)
"""

import pytest
from src.pipeline.securax_pipeline import SecuraXPipeline


@pytest.fixture(scope="module")
def pipeline():
    return SecuraXPipeline()


def test_case_1_javascript_open_redirect(pipeline):
    """
    Test 1: JavaScript Open Redirect
    Expected:
      - Language: JavaScript
      - Function: main_snippet()
      - VF: 1 (Vulnerable)
      - Expected CWE: CWE-601 (Open Redirect)
    """
    code = """function main_snippet(req, res) {
    const target = req.query.url;
    res.redirect(target);
}"""
    res = pipeline.analyze_source(code, language_override="JavaScript", refinement_cap=0)
    assert res["success"] is True, f"Pipeline failed: {res.get('error')}"
    assert len(res["rows"]) >= 1, "No analysis rows returned"

    row = res["rows"][0]
    assert row["VF"] == "Vulnerable", f"Expected Vulnerable, got {row['VF']}"
    assert "CWE-601" in row["CWE-id"], f"Expected CWE-601, got {row['CWE-id']}"
    assert "Open Redirect" in row["CWE-id"], f"Expected Open Redirect in name, got {row['CWE-id']}"


def test_case_2_python_path_traversal(pipeline):
    """
    Test 2: Python Path Traversal
    Expected:
      - Language: Python
      - Function: download_file()
      - VF: 1 (Vulnerable)
      - Expected CWE: CWE-22 (Path Traversal)
    """
    code = """import os

def download_file(filename):
    base_dir = "/var/www/uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "rb") as f:
        return f.read()"""
    res = pipeline.analyze_source(code, language_override="Python", refinement_cap=0)
    assert res["success"] is True, f"Pipeline failed: {res.get('error')}"
    assert len(res["rows"]) >= 1, "No analysis rows returned"

    row = res["rows"][0]
    assert row["VF"] == "Vulnerable", f"Expected Vulnerable, got {row['VF']}"
    assert "CWE-22" in row["CWE-id"], f"Expected CWE-22, got {row['CWE-id']}"
    assert "Path Traversal" in row["CWE-id"], f"Expected Path Traversal in name, got {row['CWE-id']}"


def test_case_3_c_integer_overflow(pipeline):
    """
    Test 3: C Integer Overflow
    Expected:
      - Language: C
      - Function: main()
      - VF: 1 (Vulnerable)
      - Expected CWE: CWE-190 (Integer Overflow)
    """
    code = """#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    size_t width = atoi(argv[1]);
    size_t height = atoi(argv[2]);
    size_t total = width * height;
    char *buf = (char *)malloc(total);
    if (!buf) return 1;
    return 0;
}"""
    res = pipeline.analyze_source(code, language_override="C", refinement_cap=0)
    assert res["success"] is True, f"Pipeline failed: {res.get('error')}"
    assert len(res["rows"]) >= 1, "No analysis rows returned"

    row = res["rows"][0]
    assert row["VF"] == "Vulnerable", f"Expected Vulnerable, got {row['VF']}"
    assert "CWE-190" in row["CWE-id"], f"Expected CWE-190, got {row['CWE-id']}"
    assert "Integer Overflow" in row["CWE-id"], f"Expected Integer Overflow in name, got {row['CWE-id']}"


def test_case_4_php_secure_file_upload(pipeline):
    """
    Test 4: PHP Secure File Upload (Hard Negative)
    Expected:
      - Language: PHP
      - Function: uploadFile()
      - VF: 0 (Safe)
      - Expected CWE: N/A
      - Refinement: Not required
    """
    code = """function uploadFile($file) {
    $allowed = ['jpg', 'png', 'pdf'];
    $filename = basename($file['name']);
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed)) {
        return false;
    }
    if ($file['size'] > 5000000) {
        return false;
    }
    $mime = mime_content_type($file['tmp_name']);
    if (!in_array($mime, ['image/jpeg', 'image/png', 'application/pdf'])) {
        return false;
    }
    $target = '/var/uploads/' . uniqid() . '.' . $ext;
    return move_uploaded_file($file['tmp_name'], $target);
}"""
    res = pipeline.analyze_source(code, language_override="PHP", refinement_cap=0)
    assert res["success"] is True, f"Pipeline failed: {res.get('error')}"
    assert len(res["rows"]) >= 1, "No analysis rows returned"

    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe"), f"Expected Safe/Controls detected, got {row['VF']}"
    assert row["CWE-id"] == "N/A", f"Expected CWE-id: N/A, got {row['CWE-id']}"
    assert row["Refined Code"] == "N/A", f"Expected Refinement N/A, got {row['Refined Code']}"
    assert row["Severity Score"] == "N/A", f"Expected Severity N/A, got {row['Severity Score']}"


def test_case_5_java_insecure_deserialization(pipeline):
    """
    Test 5: Java Insecure Deserialization
    Expected:
      - Language: Java
      - Function: readPayload()
      - VF: 1 (Vulnerable)
      - Expected CWE: CWE-502 (Insecure Deserialization)
    """
    code = """import java.io.*;

public class Deserializer {
    public Object readPayload(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}"""
    res = pipeline.analyze_source(code, language_override="Java", refinement_cap=0)
    assert res["success"] is True, f"Pipeline failed: {res.get('error')}"
    assert len(res["rows"]) >= 1, "No analysis rows returned"

    row = res["rows"][0]
    assert row["VF"] == "Vulnerable", f"Expected Vulnerable, got {row['VF']}"
    assert "CWE-502" in row["CWE-id"], f"Expected CWE-502, got {row['CWE-id']}"
    assert "Deserialization" in row["CWE-id"], f"Expected Deserialization in name, got {row['CWE-id']}"
    assert row["Snippet"] == "readPayload()", f"Expected function readPayload(), got {row['Snippet']}"

