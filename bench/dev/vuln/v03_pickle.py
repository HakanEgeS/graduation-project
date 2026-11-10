import pickle
def load_session(raw: bytes):
    return pickle.loads(raw)
