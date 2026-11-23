import subprocess

def ping_host(host):
    cmd = "ping -c 1 " + host
    subprocess.call(cmd, shell=True)
