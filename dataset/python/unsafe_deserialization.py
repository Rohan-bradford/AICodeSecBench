import hashlib
import pickle


def fingerprint(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()


def load_user_state(raw: bytes):
    return pickle.loads(raw)

