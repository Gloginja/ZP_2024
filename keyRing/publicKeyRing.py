import datetime
from Cryptodome.PublicKey import RSA


class PublicKeyRing:
    def __init__(self):
        self.keyRing = []

    def addToRing(self, timestamp: datetime, PU: RSA.RsaKey, userID: str):
        self.keyRing.append(
            {'timestamp': timestamp, 'keyID': PU.n % 2 ** 64, 'PU': PU, 'userID': userID})

    def getPU(self, keyID):
        for k in self.keyRing:
            if k['keyID'] == keyID:
                return k['PU']
        return None

    def saveKey(self, keyID):
        pass

    def deleteKey(self, keyID: int, userID: str) -> bool:
        for k in self.keyRing:
            if k['keyID'] == keyID and k['userID'] == userID:
                self.keyRing.remove(k)
                return True
        return False

    def getAllPublicKeysByUserID(self, userID: str):
        keys = []
        for k in self.keyRing:
            if k['userID'] == userID:
                keys.append(k)
        return keys
