import pickle

def deserialize_session(payload):
    # Untrusted pickle payload
    return pickle.loads(payload)
