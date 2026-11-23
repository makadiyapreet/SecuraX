"""
catalog.py — Authoritative Catalog of 50 Diverse Security Test Cases.

Contains 25 Vulnerable and 25 Secure ground-truth test cases spanning:
  - 15 Vulnerability Categories:
      1. SQL Injection (CWE-89)
      2. Cross-Site Scripting (CWE-79)
      3. Buffer Overflow (CWE-119 / CWE-120)
      4. Command Injection (CWE-78 / CWE-77)
      5. Hardcoded Credentials (CWE-798)
      6. Path Traversal (CWE-22)
      7. Insecure Deserialization (CWE-502)
      8. Weak Cryptography (CWE-327)
      9. Improper Authentication (CWE-287)
      10. Race Conditions (CWE-362)
      11. Integer Overflow (CWE-190)
      12. Insecure File Handling (CWE-732 / CWE-276)
      13. Improper Input Validation (CWE-20)
      14. Sensitive Information Exposure (CWE-200 / CWE-209)
      15. Memory Management Errors (CWE-416 / CWE-415 / CWE-476)
  - 9 Supported Languages:
      C, C++, Python, Java, JavaScript, TypeScript, PHP, Go, Ruby.
"""

from typing import List, Dict, Any

TEST_CASES: List[Dict[str, Any]] = [
    # ══════════════════════════════════════════════════════════════════════════
    # 25 VULNERABLE TEST CASES (TC-V01 to TC-V25)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "TC-V01",
        "category": "SQL Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-89",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "High",
        "vulnerable_lines": [6],
        "explanation": "Concatenates untrusted username directly into raw SQL query without parameterization",
        "remediation": "Use parameterized query with ? placeholder and tuple argument",
        "code": """import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result
""",
    },
    {
        "id": "TC-V02",
        "category": "SQL Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-89",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "High",
        "vulnerable_lines": [5],
        "explanation": "f-string interpolation of username and password into SQL statement",
        "remediation": "Use parameterized query placeholders (%s or ?)",
        "code": """import sqlite3

def authenticate(conn, user, pwd):
    cursor = conn.cursor()
    query = f"SELECT id FROM accounts WHERE user = '{user}' AND pass = '{pwd}'"
    cursor.execute(query)
    return cursor.fetchone()
""",
    },
    {
        "id": "TC-V03",
        "category": "SQL Injection",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": True,
        "expected_cwe": "CWE-89",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [3],
        "explanation": "PHP mysqli_query interpolating unescaped $_GET parameter",
        "remediation": "Use PDO or mysqli prepared statement with bind_param",
        "code": """<?php
function find_product($id) {
    global $db;
    $sql = "SELECT * FROM products WHERE id = " . $id;
    return mysqli_query($db, $sql);
}
?>""",
    },
    {
        "id": "TC-V04",
        "category": "Cross-Site Scripting",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": True,
        "expected_cwe": "CWE-79",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Medium",
        "vulnerable_lines": [3],
        "explanation": "Direct echo of untrusted parameter to HTML without htmlspecialchars",
        "remediation": "Wrap output in htmlspecialchars($user_name, ENT_QUOTES, 'UTF-8')",
        "code": """<?php
function render_welcome($user_name) {
    echo "<h1>Welcome back, " . $user_name . "!</h1>";
}
?>""",
    },
    {
        "id": "TC-V05",
        "category": "Cross-Site Scripting",
        "language": "JavaScript",
        "tier": "tier3_shared",
        "expected_vf": True,
        "expected_cwe": "CWE-79",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Medium",
        "vulnerable_lines": [3],
        "explanation": "Direct assignment of user input to innerHTML enables script injection",
        "remediation": "Assign to textContent instead of innerHTML",
        "code": """function displayComment(userComment) {
    const box = document.getElementById("comment-box");
    box.innerHTML = "<div>" + userComment + "</div>";
}
""",
    },
    {
        "id": "TC-V06",
        "category": "Buffer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-120",
        "expected_semantic_group": "Buffer-Overflow",
        "expected_severity_band": "High",
        "vulnerable_lines": [4],
        "explanation": "Unbounded strcpy into 16-byte stack buffer",
        "remediation": "Use strncpy with explicit null termination or snprintf",
        "code": """#include <string.h>

void process_input(const char *user_str) {
    char stack_buf[16];
    strcpy(stack_buf, user_str);
}
""",
    },
    {
        "id": "TC-V07",
        "category": "Buffer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-120",
        "expected_semantic_group": "Buffer-Overflow",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [4],
        "explanation": "Inherently unsafe gets() has no bound parameter and cannot prevent overflow",
        "remediation": "Replace gets(buf) with fgets(buf, sizeof(buf), stdin)",
        "code": """#include <stdio.h>

void read_line(void) {
    char buf[64];
    gets(buf);
}
""",
    },
    {
        "id": "TC-V08",
        "category": "Buffer Overflow",
        "language": "C++",
        "tier": "tier2_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-119",
        "expected_semantic_group": "Buffer-Overflow",
        "expected_severity_band": "High",
        "vulnerable_lines": [5],
        "explanation": "sprintf writing formatted integer and string into fixed-size buffer without bounds",
        "remediation": "Use snprintf(buf, sizeof(buf), ...) or std::ostringstream",
        "code": """#include <cstdio>

void format_packet(const char *name, int id) {
    char buf[32];
    sprintf(buf, "Packet: %s (id: %d)", name, id);
}
""",
    },
    {
        "id": "TC-V09",
        "category": "Command Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-78",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [4],
        "explanation": "subprocess.call with shell=True and string concatenation of host parameter",
        "remediation": "Pass list arguments ['ping', '-c', '1', host] with shell=False",
        "code": """import subprocess

def ping_host(host):
    cmd = "ping -c 1 " + host
    subprocess.call(cmd, shell=True)
""",
    },
    {
        "id": "TC-V10",
        "category": "Command Injection",
        "language": "JavaScript",
        "tier": "tier3_shared",
        "expected_vf": True,
        "expected_cwe": "CWE-78",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [4],
        "explanation": "child_process.exec concatenating unsanitized host argument",
        "remediation": "Use child_process.execFile with argument array",
        "code": """const { exec } = require('child_process');

function runDiagnostic(userHost) {
    exec("nslookup " + userHost, (err, stdout) => {
        console.log(stdout);
    });
}
""",
    },
    {
        "id": "TC-V11",
        "category": "Command Injection",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": True,
        "expected_cwe": "CWE-78",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [3],
        "explanation": "shell_exec called with unescaped argument",
        "remediation": "Sanitize parameter with escapeshellarg()",
        "code": """<?php
function convert_image($filename) {
    return shell_exec("convert " . $filename . " output.png");
}
?>""",
    },
    {
        "id": "TC-V12",
        "category": "Hardcoded Credentials",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-798",
        "expected_semantic_group": "Other-Security",
        "expected_severity_band": "High",
        "vulnerable_lines": [2],
        "explanation": "Hardcoded master API secret key in plaintext source code",
        "remediation": "Retrieve secret key from environment variable os.environ.get('API_SECRET')",
        "code": """def connect_cloud_api():
    api_key = "super_secret_production_key_12345"
    return f"Connecting with {api_key}"
""",
    },
    {
        "id": "TC-V13",
        "category": "Hardcoded Credentials",
        "language": "TypeScript",
        "tier": "tier3_shared",
        "expected_vf": True,
        "expected_cwe": "CWE-798",
        "expected_semantic_group": "Other-Security",
        "expected_severity_band": "High",
        "vulnerable_lines": [2],
        "explanation": "Hardcoded database password in source code",
        "remediation": "Read password from process.env.DB_PASSWORD",
        "code": """function getDbConfig() {
    const password = "ProductionAdminMasterPassword#2026";
    return { host: "localhost", user: "admin", password };
}
""",
    },
    {
        "id": "TC-V14",
        "category": "Path Traversal",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-22",
        "expected_semantic_group": "Path-Traversal",
        "expected_severity_band": "High",
        "vulnerable_lines": [3],
        "explanation": "Direct path concatenation allows ../ directory traversal",
        "remediation": "Verify os.path.realpath is within base directory using startswith",
        "code": """def read_user_file(filename):
    base_dir = "/var/www/uploads/"
    path = base_dir + filename
    with open(path, "r") as f:
        return f.read()
""",
    },
    {
        "id": "TC-V15",
        "category": "Path Traversal",
        "language": "Go",
        "tier": "tier3_shared",
        "expected_vf": True,
        "expected_cwe": "CWE-22",
        "expected_semantic_group": "Path-Traversal",
        "expected_severity_band": "High",
        "vulnerable_lines": [4],
        "explanation": "Unvalidated filename opened directly from base path",
        "remediation": "Use filepath.Clean and ensure target starts with base directory",
        "code": """package main
import "os"

func ReadReport(name string) ([]byte, error) {
    return os.ReadFile("/var/reports/" + name)
}
""",
    },
    {
        "id": "TC-V16",
        "category": "Insecure Deserialization",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-502",
        "expected_semantic_group": "Other-Security",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [4],
        "explanation": "pickle.loads on untrusted raw input leads to arbitrary remote code execution",
        "remediation": "Use safe JSON deserialization (json.loads) or hmac verification",
        "code": """import pickle

def deserialize_session(payload):
    # Untrusted pickle payload
    return pickle.loads(payload)
""",
    },
    {
        "id": "TC-V17",
        "category": "Weak Cryptography",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-327",
        "expected_semantic_group": "Crypto-Issues",
        "expected_severity_band": "Medium",
        "vulnerable_lines": [4],
        "explanation": "Use of broken MD5 cryptographic hash for sensitive tokens",
        "remediation": "Use SHA-256 (hashlib.sha256) or bcrypt for passwords",
        "code": """import hashlib

def hash_token(data):
    # Vulnerable: MD5 is collision-prone and broken
    return hashlib.md5(data.encode()).hexdigest()
""",
    },
    {
        "id": "TC-V18",
        "category": "Weak Cryptography",
        "language": "Java",
        "tier": "tier3_shared",
        "expected_vf": True,
        "expected_cwe": "CWE-327",
        "expected_semantic_group": "Crypto-Issues",
        "expected_severity_band": "High",
        "vulnerable_lines": [3],
        "explanation": "Use of DES cipher with 56-bit key length is cryptographically broken",
        "remediation": "Use AES/GCM/NoPadding with 256-bit key",
        "code": """import javax.crypto.Cipher;

public class Cryptor {
    public static Cipher getCipher() throws Exception {
        return Cipher.getInstance("DES");
    }
}
""",
    },
    {
        "id": "TC-V19",
        "category": "Improper Authentication",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-287",
        "expected_semantic_group": "Access-Control",
        "expected_severity_band": "Critical",
        "vulnerable_lines": [3],
        "explanation": "Hardcoded bypass allows anyone to authenticate as admin",
        "remediation": "Remove hardcoded credentials and query database with password hashing",
        "code": """def check_credentials(username, password):
    if username == "admin":
        return True
    return False
""",
    },
    {
        "id": "TC-V20",
        "category": "Race Conditions",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-362",
        "expected_semantic_group": "Race-Condition",
        "expected_severity_band": "Medium",
        "vulnerable_lines": [4],
        "explanation": "Unsynchronized increment of shared global counter across threads",
        "remediation": "Protect counter increment with mutex lock (pthread_mutex_lock)",
        "code": """static int shared_counter = 0;

void increment_counter(void) {
    // Race condition on shared counter
    shared_counter++;
}
""",
    },
    {
        "id": "TC-V21",
        "category": "Integer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-190",
        "expected_semantic_group": "Integer-Issues",
        "expected_severity_band": "High",
        "vulnerable_lines": [4],
        "explanation": "Multiplication can overflow size_t leading to undersized buffer allocation",
        "remediation": "Check for overflow before multiplication: if (count > SIZE_MAX / size) return NULL;",
        "code": """#include <stdlib.h>

void *allocate_matrix(size_t width, size_t height) {
    size_t total = width * height;
    return malloc(total);
}
""",
    },
    {
        "id": "TC-V22",
        "category": "Insecure File Handling",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-732",
        "expected_semantic_group": "Access-Control",
        "expected_severity_band": "Medium",
        "vulnerable_lines": [4],
        "explanation": "Creates world-writable/readable file with permissions 0o777",
        "remediation": "Set restrictive file permissions such as 0o600 (owner read/write only)",
        "code": """import os

def create_shared_file(path):
    with open(path, "w") as f:
        f.write("data")
    os.chmod(path, 0o777)
""",
    },
    {
        "id": "TC-V23",
        "category": "Improper Input Validation",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-20",
        "expected_semantic_group": "Input-Validation",
        "expected_severity_band": "High",
        "vulnerable_lines": [3],
        "explanation": "eval() executes untrusted arbitrary Python expression",
        "remediation": "Use ast.literal_eval for safe literal evaluation",
        "code": """def calculate_expression(user_input):
    # Vulnerable: arbitrary code execution via eval
    return eval(user_input)
""",
    },
    {
        "id": "TC-V24",
        "category": "Sensitive Information Exposure",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": True,
        "expected_cwe": "CWE-209",
        "expected_semantic_group": "Info-Exposure",
        "expected_severity_band": "Low",
        "vulnerable_lines": [6],
        "explanation": "Raw database error traceback leaked directly to HTTP client response",
        "remediation": "Log exception internally and return generic error message",
        "code": """import traceback

def handle_request(req):
    try:
        process_db(req)
    except Exception as e:
        return f"Database error details: {traceback.format_exc()}"
""",
    },
    {
        "id": "TC-V25",
        "category": "Memory Management Errors",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": True,
        "expected_cwe": "CWE-416",
        "expected_semantic_group": "Use-After-Free",
        "expected_severity_band": "High",
        "vulnerable_lines": [5],
        "explanation": "Pointers dereferenced after memory block was freed",
        "remediation": "Do not access freed pointer; set ptr = NULL after free",
        "code": """#include <stdlib.h>

void use_after_free(char *ptr) {
    free(ptr);
    // Vulnerable: reading from freed pointer
    char c = *ptr;
}
""",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 25 SECURE TEST CASES (TC-S01 to TC-S25)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "TC-S01",
        "category": "SQL Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Secure parameterized SQL query using ? placeholder and argument tuple",
        "remediation": "None required",
        "code": """import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchall()
    conn.close()
    return result
""",
    },
    {
        "id": "TC-S02",
        "category": "SQL Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Secure parameterized query passing arguments as tuple",
        "remediation": "None required",
        "code": """import sqlite3

def authenticate(conn, user, pwd):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM accounts WHERE user = ? AND pass = ?", (user, pwd))
    return cursor.fetchone()
""",
    },
    {
        "id": "TC-S03",
        "category": "SQL Injection",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Secure PDO prepared statement with parameterized integer binding",
        "remediation": "None required",
        "code": """<?php
function find_product($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id");
    $stmt->execute(['id' => (int)$id]);
    return $stmt->fetch();
}
?>""",
    },
    {
        "id": "TC-S04",
        "category": "Cross-Site Scripting",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "HTML output properly escaped using htmlspecialchars",
        "remediation": "None required",
        "code": """<?php
function render_welcome($user_name) {
    $safe = htmlspecialchars($user_name, ENT_QUOTES, 'UTF-8');
    echo "<h1>Welcome back, " . $safe . "!</h1>";
}
?>""",
    },
    {
        "id": "TC-S05",
        "category": "Cross-Site Scripting",
        "language": "JavaScript",
        "tier": "tier3_shared",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Assigning to textContent avoids DOM HTML interpretation",
        "remediation": "None required",
        "code": """function displayComment(userComment) {
    const box = document.getElementById("comment-box");
    box.textContent = userComment;
}
""",
    },
    {
        "id": "TC-S06",
        "category": "Buffer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "strncpy with explicit buffer bound and mandatory null termination",
        "remediation": "None required",
        "code": """#include <string.h>

void process_input(const char *user_str) {
    char stack_buf[16];
    strncpy(stack_buf, user_str, sizeof(stack_buf) - 1);
    stack_buf[sizeof(stack_buf) - 1] = '\\0';
}
""",
    },
    {
        "id": "TC-S07",
        "category": "Buffer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "fgets bounds maximum read characters to buffer size",
        "remediation": "None required",
        "code": """#include <stdio.h>

void read_line(void) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        printf("Read: %s", buf);
    }
}
""",
    },
    {
        "id": "TC-S08",
        "category": "Buffer Overflow",
        "language": "C++",
        "tier": "tier2_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "snprintf restricts formatted output to buffer capacity",
        "remediation": "None required",
        "code": """#include <cstdio>

void format_packet(const char *name, int id) {
    char buf[32];
    snprintf(buf, sizeof(buf), "Packet: %s (id: %d)", name, id);
}
""",
    },
    {
        "id": "TC-S09",
        "category": "Command Injection",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "subprocess.run with argument array and shell=False prevents command injection",
        "remediation": "None required",
        "code": """import subprocess

def ping_host(host):
    # Safe: no shell invocation
    subprocess.run(["ping", "-c", "1", host], check=True, shell=False)
""",
    },
    {
        "id": "TC-S10",
        "category": "Command Injection",
        "language": "JavaScript",
        "tier": "tier3_shared",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "execFile with argument array does not invoke shell interpreter",
        "remediation": "None required",
        "code": """const { execFile } = require('child_process');

function runDiagnostic(userHost) {
    execFile("nslookup", [userHost], (err, stdout) => {
        console.log(stdout);
    });
}
""",
    },
    {
        "id": "TC-S11",
        "category": "Command Injection",
        "language": "PHP",
        "tier": "tier2_php",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Parameter safely escaped using escapeshellarg",
        "remediation": "None required",
        "code": """<?php
function convert_image($filename) {
    $safe = escapeshellarg($filename);
    return shell_exec("convert " . $safe . " output.png");
}
?>""",
    },
    {
        "id": "TC-S12",
        "category": "Hardcoded Credentials",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Credentials loaded securely from environment variable",
        "remediation": "None required",
        "code": """import os

def connect_cloud_api():
    api_key = os.environ.get("API_SECRET")
    if not api_key:
        raise ValueError("API_SECRET not set")
    return "Connected"
""",
    },
    {
        "id": "TC-S13",
        "category": "Hardcoded Credentials",
        "language": "TypeScript",
        "tier": "tier3_shared",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Database password read from process.env",
        "remediation": "None required",
        "code": """function getDbConfig() {
    const password = process.env.DB_PASSWORD || "";
    return { host: "localhost", user: "admin", password };
}
""",
    },
    {
        "id": "TC-S14",
        "category": "Path Traversal",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "os.path.basename strips directory traversal tokens; realpath verified within base",
        "remediation": "None required",
        "code": """import os

def read_user_file(filename):
    base_dir = "/var/www/uploads"
    safe_name = os.path.basename(filename)
    path = os.path.join(base_dir, safe_name)
    with open(path, "r") as f:
        return f.read()
""",
    },
    {
        "id": "TC-S15",
        "category": "Path Traversal",
        "language": "Go",
        "tier": "tier3_shared",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "filepath.Base prevents path traversal by extracting clean basename",
        "remediation": "None required",
        "code": """package main
import (
    "os"
    "path/filepath"
)

func ReadReport(name string) ([]byte, error) {
    clean := filepath.Base(name)
    return os.ReadFile("/var/reports/" + clean)
}
""",
    },
    {
        "id": "TC-S16",
        "category": "Insecure Deserialization",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "json.loads is safe against remote code execution",
        "remediation": "None required",
        "code": """import json

def deserialize_session(payload):
    # Safe JSON parser
    return json.loads(payload)
""",
    },
    {
        "id": "TC-S17",
        "category": "Weak Cryptography",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "hashlib.sha256 provides secure collision-resistant hashing",
        "remediation": "None required",
        "code": """import hashlib

def hash_token(data):
    # Secure SHA-256
    return hashlib.sha256(data.encode()).hexdigest()
""",
    },
    {
        "id": "TC-S18",
        "category": "Weak Cryptography",
        "language": "Java",
        "tier": "tier3_shared",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "AES with GCM authenticated mode is industry standard",
        "remediation": "None required",
        "code": """import javax.crypto.Cipher;

public class Cryptor {
    public static Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
""",
    },
    {
        "id": "TC-S19",
        "category": "Improper Authentication",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Uses secure constant-time password comparison against hashed store",
        "remediation": "None required",
        "code": """import hmac

def verify_token(user_token, stored_hash):
    return hmac.compare_digest(user_token, stored_hash)
""",
    },
    {
        "id": "TC-S20",
        "category": "Race Conditions",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Counter protected by pthread_mutex_lock synchronization",
        "remediation": "None required",
        "code": """#include <pthread.h>

static int shared_counter = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void increment_counter(void) {
    pthread_mutex_lock(&lock);
    shared_counter++;
    pthread_mutex_unlock(&lock);
}
""",
    },
    {
        "id": "TC-S21",
        "category": "Integer Overflow",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Pre-check verifies multiplication does not exceed SIZE_MAX",
        "remediation": "None required",
        "code": """#include <stdlib.h>
#include <stdint.h>

void *allocate_matrix(size_t width, size_t height) {
    if (height != 0 && width > SIZE_MAX / height) {
        return NULL;
    }
    return malloc(width * height);
}
""",
    },
    {
        "id": "TC-S22",
        "category": "Insecure File Handling",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Restrictive permissions 0o600 (owner-only read/write)",
        "remediation": "None required",
        "code": """import os

def create_private_file(path):
    with open(path, "w") as f:
        f.write("data")
    os.chmod(path, 0o600)
""",
    },
    {
        "id": "TC-S23",
        "category": "Improper Input Validation",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "ast.literal_eval parses literals without code execution",
        "remediation": "None required",
        "code": """import ast

def parse_safely(user_input):
    return ast.literal_eval(user_input)
""",
    },
    {
        "id": "TC-S24",
        "category": "Sensitive Information Exposure",
        "language": "Python",
        "tier": "tier2_python",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Internal errors logged privately; generic message returned to client",
        "remediation": "None required",
        "code": """import logging

logger = logging.getLogger("api")

def handle_request(req):
    try:
        process_db(req)
        return "Success"
    except Exception as e:
        logger.error("DB error: %s", e)
        return "An internal server error occurred"
""",
    },
    {
        "id": "TC-S25",
        "category": "Memory Management Errors",
        "language": "C",
        "tier": "tier1_c_cpp",
        "expected_vf": False,
        "expected_cwe": "N/A",
        "expected_semantic_group": "Safe",
        "expected_severity_band": "None",
        "vulnerable_lines": [],
        "explanation": "Memory read before free; pointer set to NULL after free",
        "remediation": "None required",
        "code": """#include <stdlib.h>

char read_and_free(char *ptr) {
    if (!ptr) return 0;
    char c = *ptr;
    free(ptr);
    ptr = NULL;
    return c;
}
""",
    },
]

