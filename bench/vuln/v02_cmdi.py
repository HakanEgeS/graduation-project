import subprocess
def ping(host: str):
    return subprocess.check_output("ping -c 1 " + host, shell=True)
