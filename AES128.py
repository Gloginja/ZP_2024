import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


class AES128:
    @staticmethod
    def generateKey() -> bytes:
        return get_random_bytes(16)

    @staticmethod
    def encrypt(message: str, key: bytes) -> dict:
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(b64encode(message.encode('utf-8')), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ciphertext = b64encode(ct_bytes).decode('utf-8')
        return {'ciphertext': ciphertext, 'iv': iv}

    @staticmethod
    def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> str:
        cipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
        plaintext = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
        return b64decode(plaintext).decode('utf-8')
