import os

def create_private_file(path):
    with open(path, "w") as f:
        f.write("data")
    os.chmod(path, 0o600)
