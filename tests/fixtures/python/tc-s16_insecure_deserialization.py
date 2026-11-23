import json

def deserialize_session(payload):
    # Safe JSON parser
    return json.loads(payload)
