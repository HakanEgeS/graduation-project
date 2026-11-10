import json
def load_session(raw: bytes):
    return json.loads(raw)
