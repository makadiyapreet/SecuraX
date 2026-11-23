import os

def connect_cloud_api():
    api_key = os.environ.get("API_SECRET")
    if not api_key:
        raise ValueError("API_SECRET not set")
    return "Connected"
