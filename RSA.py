import rsa


class RSA:
    @staticmethod
    def encrypt(key: rsa.PublicKey, message: bytes) -> bytes:
        return rsa.encrypt(message, key)

    @staticmethod
    def decrypt(key: rsa.PrivateKey, ciphertext: bytes) -> bytes:
        return rsa.decrypt(ciphertext, key)

    @staticmethod
    def sign(key: rsa.PrivateKey, message: bytes) -> bytes:
        return rsa.sign(message, key, 'SHA-1')

    @staticmethod
    def verify(key: rsa.PublicKey, message: bytes, signature) -> bool:
        return rsa.verify(message, signature, key) == 'SHA-1'
