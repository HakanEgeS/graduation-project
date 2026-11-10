import hashlib, os
def hash_password(pw: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
