import os

def create_shared_file(path):
    with open(path, "w") as f:
        f.write("data")
    os.chmod(path, 0o777)
