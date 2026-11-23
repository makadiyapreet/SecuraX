import os

def read_user_file(filename):
    base_dir = "/var/www/uploads"
    safe_name = os.path.basename(filename)
    path = os.path.join(base_dir, safe_name)
    with open(path, "r") as f:
        return f.read()
