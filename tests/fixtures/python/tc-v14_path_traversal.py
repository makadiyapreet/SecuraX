def read_user_file(filename):
    base_dir = "/var/www/uploads/"
    path = base_dir + filename
    with open(path, "r") as f:
        return f.read()
