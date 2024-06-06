from datetime import datetime

from Cryptodome.PublicKey.RSA import RsaKey

from PGPMessage import PGPMessage
from keyRing.keyRingManager import KeyRingManager
from user import users, User


class PGP:
    def __init__(self):
        self.keyRingManager = KeyRingManager()

    def generateNewPairKeys(self, name: str, email: str, password: str, keySize: int):
        users.append(User(email=email, name=name, password=password))
        self.keyRingManager.generateNewPairRSA(keySize=keySize, userID=email, password=password)

    def send(self, filepath: str, PR: RsaKey, PU: RsaKey, isCompressed: bool, algo: int, keyID: int, messageText: str):
        pgpMessage = PGPMessage(datetime.now(), messageText)
        pgpMessage.save(filePath=filepath, PR=PR, PU=PU, isCompressed=isCompressed, algo=algo, keyID=keyID)

    def receive(self, ):
        pass
