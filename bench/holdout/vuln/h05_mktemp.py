import tempfile


def write_report(text: str) -> str:
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as fh:
        fh.write(text)
    return path
