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

    def send(self, filepath: str, PR: RsaKey | None, PU: RsaKey | None, isCompressed: bool, algo: int, messageText: str):
        pgpMessage = PGPMessage(datetime.now(), messageText)
        pgpMessage.save(filePath=filepath, PR=PR, PU=PU, isCompressed=isCompressed, algo=algo)

    def receive(self, message_data:  dict, krm: KeyRingManager, password=None):
        pgpMessage = PGPMessage()
        pgpMessage.load(message_data, krm, password)
        return pgpMessage.message
