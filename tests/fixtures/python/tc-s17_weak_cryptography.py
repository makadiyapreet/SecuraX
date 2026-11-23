import hashlib

def hash_token(data):
    # Secure SHA-256
    return hashlib.sha256(data.encode()).hexdigest()
