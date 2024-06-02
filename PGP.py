from keyRing.keyRingManager import KeyRingManager
from user import users, User


class PGP:
    def __init__(self):
        self.keyRingManager = KeyRingManager()

    def generateNewPairKeys(self, name: str, email: str, password: str, keySize: int):
        users.append(User(email=email, name=name, password=password))
        self.keyRingManager.generateNewPairRSA(keySize=keySize, userID=email, password=password)

    def send(self, ):
        pass

    def receive(self, ):
        pass