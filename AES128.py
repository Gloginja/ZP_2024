import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AES128:
    @staticmethod
    def generateKey() -> bytes:
        return get_random_bytes(16)

    @staticmethod
    def encrypt(key: bytes, message: str) -> dict:
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
        return {'ciphertext': ciphertext, 'iv': iv}

    @staticmethod
    def decrypt(key: bytes, message: dict) -> str:
        iv = base64.b64decode(message['iv'])
        ct = base64.b64decode(message['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)
        return plaintext.decode('utf-8')
