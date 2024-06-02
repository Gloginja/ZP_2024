import traceback

from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import PKCS1_OAEP


class RSA_Algo:
    @staticmethod
    def encrypt(key: RSA.RsaKey, message: bytes) -> bytes:
        return PKCS1_OAEP.new(key).encrypt(message)

    @staticmethod
    def decrypt(key: RSA.RsaKey, ciphertext: bytes) -> bytes:
        return PKCS1_OAEP.new(key).decrypt(ciphertext)

    @staticmethod
    def sign(key: RSA.RsaKey, message: bytes) -> bytes | None:
        if key.can_sign():
            return pkcs1_15.new(key).sign(SHA1.new(message))
        return None

    @staticmethod
    def verify(key: RSA.RsaKey, message: bytes, signature: bytes) -> bool:
        try:
            pkcs1_15.new(key).verify(SHA1.new(message), signature)
            return True
        except (ValueError, TypeError):
            return False
