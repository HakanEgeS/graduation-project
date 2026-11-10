from Crypto.Cipher import DES


def encrypt_card(key: bytes, data: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
