
import os
import hmac
import html
import secrets
import hashlib
import subprocess
import pickle
from pathlib import Path


# ============================================
# SAFE FUNCTIONS (15)
# ============================================

def safe_division(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a / b


def safe_password_hash(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return salt.hex() + ":" + hashed.hex()


def safe_password_verify(password, stored):
    salt_hex, hash_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )
    return hmac.compare_digest(actual, expected)


def safe_token():
    return secrets.token_urlsafe(32)


def safe_command(user_input):
    return subprocess.run(
        ["echo", user_input],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=True
    ).stdout


def safe_html(user_input):
    return html.escape(user_input, quote=True)


def safe_compare_tokens(token1, token2):
    return hmac.compare_digest(
        token1.encode(), token2.encode()
    )


def safe_password_reset_token():
    return secrets.token_hex(32)


def safe_generate_session_id():
    return secrets.token_urlsafe(48)


def safe_generate_api_key():
    return secrets.token_urlsafe(48)


def safe_auth_token():
    return secrets.token_hex(32)


def safe_csrf_token():
    return secrets.token_urlsafe(32)


def safe_verify_csrf_token(provided, expected):
    return hmac.compare_digest(
        provided.encode(), expected.encode()
    )


def safe_generate_nonce():
    return secrets.token_hex(16)


def safe_sha256_checksum(data):
    if not isinstance(data, bytes):
        raise TypeError("Expected bytes")
    return hashlib.sha256(data).hexdigest()


# ============================================
# VULNERABLE FUNCTIONS (5)
# Educational examples: do not execute with
# untrusted input.
# ============================================

# CWE-89: SQL Injection
def vulnerable_sql(connection, username):
    query = (
        "SELECT * FROM users WHERE username = '"
        + username + "'"
    )
    return connection.execute(query).fetchall()


# CWE-78: OS Command Injection
def vulnerable_command(user_input):
    return subprocess.run(
        "echo " + user_input,
        shell=True,
        capture_output=True,
        text=True
    ).stdout


# CWE-94: Code Injection
def vulnerable_eval(user_input):
    return eval(user_input)


# CWE-22: Path Traversal
def vulnerable_file_read(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()


# CWE-502: Unsafe Deserialization
def vulnerable_deserialization(data):
    return pickle.loads(data)
