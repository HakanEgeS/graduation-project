import subprocess
def ping(host: str):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False).stdout
