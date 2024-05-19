import rsa
import getpass


class RSA:
    def __init__(self):
        self.public_keys = {}
        self.private_keys = {}

    @staticmethod
    def encrypt(plaintext, key) -> bytes:
        return rsa.encrypt(plaintext, key)

    @staticmethod
    def decrypt(ciphertext, key):
        return rsa.decrypt(ciphertext, key)

    def generate_keys(self):
        name = input("Enter your name: ")
        email = input("Enter your email: ")
        key_size = int(input("Enter key size (1024 or 2048 bits): "))
        (pubkey, privkey) = rsa.newkeys(key_size)
        self.public_keys[name] = pubkey
        password = getpass.getpass("Enter a password to protect your private key: ")
        self.private_keys[name] = (privkey, password)

    def store_keys(self, name):
        password = getpass.getpass("Enter your password to store your private key: ")
        if name in self.private_keys and self.private_keys[name][1] == password:
            with open(f'{name}_private.pem', 'w') as f:
                f.write(self.private_keys[name][0].save_pkcs1().decode())
            print(f"Private key for {name} stored successfully.")
        else:
            print("Incorrect password or user does not exist.")

    def access_private_key(self, name):
        password = getpass.getpass("Enter your password to access your private key: ")
        if name in self.private_keys and self.private_keys[name][1] == password:
            return self.private_keys[name][0]
        else:
            print("Incorrect password or user does not exist.")
            return None
