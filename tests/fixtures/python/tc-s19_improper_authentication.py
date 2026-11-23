import hmac

def verify_token(user_token, stored_hash):
    return hmac.compare_digest(user_token, stored_hash)
