"""
test_hard_negatives.py — Dedicated Hard-Negative Evaluation Suite.

Evaluates SecuraX on defensibly secure implementations that superficially resemble
vulnerabilities (e.g. contain file handling, SQL words, exec calls, or memory operations),
verifying that independent security validation correctly confirms safety (VF=0 / Safe).
"""

import pytest
from src.pipeline.securax_pipeline import SecuraXPipeline


@pytest.fixture(scope="module")
def pipeline():
    return SecuraXPipeline()


def test_hard_negative_parameterized_sql_python(pipeline):
    """Python: Parameterized SQL using DB-API ? placeholders (CWE-89 hard negative)."""
    code = """import sqlite3

def query_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return cursor.fetchone()"""
    res = pipeline.analyze_source(code, language_override="Python", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_parameterized_sql_php(pipeline):
    """PHP: Parameterized query using PDO prepared statement (CWE-89 hard negative)."""
    code = """function get_account($pdo, $account_id) {
    $stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = :id");
    $stmt->execute(['id' => $account_id]);
    return $stmt->fetch();
}"""
    res = pipeline.analyze_source(code, language_override="PHP", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_safe_dom_javascript(pipeline):
    """JavaScript: Safe DOM assignment using textContent instead of innerHTML (CWE-79 hard negative)."""
    code = """function displayMessage(userText) {
    const el = document.getElementById('output');
    el.textContent = userText;
}"""
    res = pipeline.analyze_source(code, language_override="JavaScript", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_escaped_html_php(pipeline):
    """PHP: Echoing untrusted variable escaped via htmlspecialchars (CWE-79 hard negative)."""
    code = """function render_profile($name) {
    echo "<h1>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";
}"""
    res = pipeline.analyze_source(code, language_override="PHP", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_safe_command_python(pipeline):
    """Python: Safe subprocess invocation with argument vector and no shell=True (CWE-78 hard negative)."""
    code = """import subprocess

def ping_host(host_ip):
    # Argument array without shell=True avoids command injection
    res = subprocess.run(["ping", "-c", "2", host_ip], capture_output=True, text=True)
    return res.stdout"""
    res = pipeline.analyze_source(code, language_override="Python", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_safe_command_php(pipeline):
    """PHP: Command execution with parameter sanitized using escapeshellarg (CWE-78 hard negative)."""
    code = """function test_connection($host) {
    $clean_host = escapeshellarg($host);
    return shell_exec("ping -c 1 " . $clean_host);
}"""
    res = pipeline.analyze_source(code, language_override="PHP", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_path_basename_python(pipeline):
    """Python: Path resolution protected by os.path.basename (CWE-22 hard negative)."""
    code = """import os

def load_attachment(user_filename):
    safe_name = os.path.basename(user_filename)
    safe_path = os.path.join("/var/data/files", safe_name)
    with open(safe_path, "rb") as f:
        return f.read()"""
    res = pipeline.analyze_source(code, language_override="Python", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_integer_overflow_check_c(pipeline):
    """C: Multiplication protected by overflow boundary pre-check (CWE-190 hard negative)."""
    code = """#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void *safe_alloc_matrix(size_t width, size_t height) {
    if (width > 0 && height > SIZE_MAX / width) {
        return NULL; // Overflow prevented
    }
    size_t total = width * height;
    return malloc(total);
}"""
    res = pipeline.analyze_source(code, language_override="C", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"


def test_hard_negative_bounded_copy_c(pipeline):
    """C: Bounded string copy using strncpy with explicit destination bounds (CWE-119 hard negative)."""
    code = """#include <string.h>

void safe_copy(char *dest, const char *src) {
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\\0';
}"""
    res = pipeline.analyze_source(code, language_override="C", refinement_cap=0)
    assert res["success"] is True
    row = res["rows"][0]
    assert row["VF"] in ("Safe", "Controls detected - likely safe")
    assert row["CWE-id"] == "N/A"

