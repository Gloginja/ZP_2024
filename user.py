import hashlib
import base64

users: list = []


def hashPass(password: str) -> str:
    return hashlib.sha1(base64.b64encode(password.encode('ascii'))).hexdigest()


def getUserDataByEmail(email: str):
    for u in users:
        if u.email == email:
            return u
    return None


class User:
    def __init__(self, email: str, password: str, name: str):
        self.name = name
        self.email = email
        self.password = hashPass(password)

    def checkPassword(self, password):
        return self.password == hashPass(password)
