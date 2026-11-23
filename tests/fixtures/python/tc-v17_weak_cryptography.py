import hashlib

def hash_token(data):
    # Vulnerable: MD5 is collision-prone and broken
    return hashlib.md5(data.encode()).hexdigest()
