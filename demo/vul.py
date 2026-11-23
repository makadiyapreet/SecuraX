# SecuraX Vulnerability Detection Test Suite
# Contains intentionally vulnerable functions for educational testing.

import os
import sqlite3
import subprocess
import tempfile

# CWE-78: OS Command Injection
def test_command_injection(user_input):
    os.system("echo " + user_input)


# CWE-89: SQL Injection
def test_sql_injection(user_input):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)


# CWE-22: Path Traversal
def test_path_traversal(user_input):
    filename = "/tmp/" + user_input
    with open(filename, "r") as f:
        return f.read()


# CWE-798: Hardcoded Credentials
def test_hardcoded_password():
    username = "admin"
    password = "admin123"
    return username, password


# CWE-327: Weak Cryptography
def test_weak_crypto():
    import hashlib
    password = "secret123"
    return hashlib.md5(password.encode()).hexdigest()


# CWE-502: Unsafe Deserialization
def test_unsafe_deserialization(data):
    import pickle
    return pickle.loads(data)


# CWE-338: Weak Randomness
def test_weak_random():
    import random
    return random.randint(1000, 9999)


# CWE-377: Insecure Temporary File
def test_insecure_temp_file():
    filename = "/tmp/secura_temp.txt"
    with open(filename, "w") as f:
        f.write("sensitive data")
    return filename


# CWE-94: Code Injection
def test_eval_injection(user_input):
    return eval(user_input)


# CWE-22: Directory Traversal
def test_directory_traversal(user_input):
    return open(user_input, "r").read()


# CWE-732: Incorrect Permissions
def test_unsafe_permissions(filename):
    os.chmod(filename, 0o777)


# CWE-120: Buffer Overflow (C-like risk is not directly applicable in Python)
def test_unsafe_buffer():
    buffer = bytearray(10)
    data = b"A" * 100
    buffer[:len(data)] = data
    return buffer


# CWE-209: Information Exposure
def test_information_exposure():
    try:
        1 / 0
    except Exception as e:
        print("Internal error:", str(e))


# CWE-22: Unsafe File Access
def test_unsafe_file_access(user_input):
    with open(user_input, "w") as f:
        f.write("user-controlled content")


# CWE-312: Cleartext Storage
def test_cleartext_storage():
    with open("passwords.txt", "w") as f:
        f.write("password=admin123")


# CWE-327: Weak Hashing
def test_weak_hash():
    import hashlib
    return hashlib.sha1(b"password").hexdigest()


# CWE-362: Race Condition
shared_counter = 0

def test_race_condition():
    global shared_counter
    shared_counter += 1


# CWE-369: Divide by Zero
def test_division_by_zero(value):
    return 100 / value


# CWE-476: NULL Pointer-like issue
def test_none_dereference(value):
    return value.upper()


# CWE-190: Integer Overflow (Python integers do not overflow normally)
def test_integer_overflow(value):
    return value * value


# CWE-117: Log Injection
def test_log_injection(user_input):
    print("Login attempt: " + user_input)


# CWE-732: Insecure File Permissions
def test_world_writable_file():
    with open("secret.txt", "w") as f:
        f.write("secret")
    os.chmod("secret.txt", 0o666)


# CWE-434: Unrestricted File Upload (logic simulation)
def test_file_upload(filename):
    destination = "/tmp/uploads/" + filename
    return destination


# CWE-639: Authorization Bypass (logic simulation)
def test_authorization(user_id, requested_id):
    if user_id:
        return "Access granted"
    return "Access denied"


# CWE-400: Resource Exhaustion
def test_resource_exhaustion(size):
    return "A" * size


# CWE-295: Certificate Validation Issue (simulation)
def test_certificate_validation():
    verify_ssl = False
    return verify_ssl


# CWE-327: Weak Encryption Configuration
def test_weak_encryption_config():
    algorithm = "DES"
    return algorithm


# CWE-798: Embedded API Key
def test_embedded_api_key():
    API_KEY = "sk_test_example_hardcoded_key_123456"
    return API_KEY


# CWE-601: Open Redirect (logic simulation)
def test_open_redirect(url):
    return url


# CWE-20: Improper Input Validation
def test_missing_validation(age):
    return int(age)


# CWE-772: Missing Resource Release
def test_resource_leak():
    f = open("test.txt", "w")
    f.write("data")
    # File not explicitly closed


# CWE-134 equivalent concept: Unsafe formatted output
def test_unsafe_format(user_input):
    return user_input % "data"


# CWE-611: XML External Entity (XXE) — unsafe parser configuration
def test_xml_parser(xml_data):
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_data, parser)


# CWE-79: HTML Injection / XSS (logic simulation)
def test_html_injection(user_input):
    return "<html>" + user_input + "</html>"


# CWE-1333: ReDoS
def test_regex_dos(user_input):
    import re
    return re.match(r"(a+)+$", user_input)


# CWE-295: Insecure TLS (simulation)
def test_insecure_tls():
    return {"verify": False}