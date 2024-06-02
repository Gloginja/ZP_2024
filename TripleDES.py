from base64 import b64encode, b64decode

from Cryptodome.Cipher import DES3
from Cryptodome.Random import get_random_bytes


class TripleDES:
    @staticmethod
    def generateKey() -> bytes:
        return DES3.adjust_key_parity(get_random_bytes(24))

    @staticmethod
    def encrypt(plaintext: str, key: bytes):
        cipher = DES3.new(key, DES3.MODE_CFB)
        return {'iv': b64encode(cipher.iv).decode('utf-8'), 'ciphertext': b64encode(cipher.encrypt(plaintext.encode('utf-8'))).decode('utf-8')}

    @staticmethod
    def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> str:
        cipher = DES3.new(key=key, mode=DES3.MODE_CFB, iv=b64decode(iv))
        return cipher.decrypt(b64decode(ciphertext)).decode('utf-8')
