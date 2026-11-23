import subprocess

def ping_host(host):
    # Safe: no shell invocation
    subprocess.run(["ping", "-c", "1", host], check=True, shell=False)
