
import os
import hmac
import html
import secrets
import hashlib
import subprocess
import base64


# ============================================
# SECURAX - LARGE SAFE CODE TEST
# Total Functions: 25
# Intentionally Vulnerable Functions: 0
# ============================================


# 1. Safe Division
def safe_division(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a / b


# 2. Secure Password Hashing
def safe_password_hash(password):
    salt = os.urandom(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return salt.hex() + ":" + hashed.hex()


# 3. Secure Password Verification
def safe_password_verify(password, stored):
    salt_hex, hash_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return hmac.compare_digest(actual, expected)


# 4. Secure Token Generation
def safe_token():
    return secrets.token_urlsafe(32)


# 5. Safe Command Execution
def safe_command(user_input):
    return subprocess.run(
        ["echo", user_input],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=True
    ).stdout


# 6. HTML Escaping
def safe_html(user_input):
    return html.escape(user_input, quote=True)


# 7. Constant-Time Token Comparison
def safe_compare_tokens(token1, token2):
    return hmac.compare_digest(
        token1.encode("utf-8"),
        token2.encode("utf-8")
    )


# 8. Secure Password Reset Token
def safe_password_reset_token():
    return secrets.token_hex(32)


# 9. Secure Session Identifier
def safe_generate_session_id():
    return secrets.token_urlsafe(48)


# 10. Secure API Key Generation
def safe_generate_api_key():
    return secrets.token_urlsafe(48)


# 11. Secure Authentication Token
def safe_auth_token():
    return secrets.token_hex(32)


# 12. Secure CSRF Token
def safe_csrf_token():
    return secrets.token_urlsafe(32)


# 13. CSRF Token Verification
def safe_verify_csrf_token(provided, expected):
    return hmac.compare_digest(
        provided.encode("utf-8"),
        expected.encode("utf-8")
    )


# 14. Secure Nonce Generation
def safe_generate_nonce():
    return secrets.token_hex(16)


# 15. Safe Text Encoding
def safe_encode_text(text):
    if not isinstance(text, str):
        raise TypeError("Expected string")

    return text.encode("utf-8")


# 16. Safe Text Decoding
def safe_decode_text(data):
    if not isinstance(data, bytes):
        raise TypeError("Expected bytes")

    return data.decode("utf-8", errors="strict")


# 17. Safe Base64 Encoding
def safe_base64_encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Expected bytes")

    return base64.b64encode(data).decode("ascii")


# 18. Safe Base64 Decoding
def safe_base64_decode(encoded):
    if not isinstance(encoded, str):
        raise TypeError("Expected string")

    return base64.b64decode(
        encoded,
        validate=True
    )


# 19. Secure SHA-256 Checksum
def safe_sha256_checksum(data):
    if not isinstance(data, bytes):
        raise TypeError("Expected bytes")

    return hashlib.sha256(data).hexdigest()


# 20. Secure SHA-512 Checksum
def safe_sha512_checksum(data):
    if not isinstance(data, bytes):
        raise TypeError("Expected bytes")

    return hashlib.sha512(data).hexdigest()


# 21. Safe HTML Attribute Escaping
def safe_escape_attribute(value):
    return html.escape(value, quote=True)


# 22. Safe Environment Variable Lookup
def safe_get_environment(name):
    allowed = {
        "APP_MODE",
        "APP_VERSION",
        "APP_REGION"
    }

    if name not in allowed:
        raise ValueError("Environment variable not allowed")

    return os.environ.get(name)


# 23. Safe String Length Check
def safe_check_length(text):
    if not isinstance(text, str):
        raise TypeError("Expected string")

    return len(text) <= 256


# 24. Safe Secret Comparison
def safe_verify_secret(provided, expected):
    if not isinstance(provided, str):
        return False

    if not isinstance(expected, str):
        return False

    return hmac.compare_digest(
        provided.encode("utf-8"),
        expected.encode("utf-8")
    )


# 25. Safe Security Header Configuration
def safe_security_headers():
    return {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'",
        "Cache-Control": "no-store"
    }
