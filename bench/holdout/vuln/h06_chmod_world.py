import os


def publish_key(path: str) -> None:
    os.chmod(path, 0o777)
