from keyRing.privateKeyRing import PrivateKeyRing
from keyRing.publicKeyRing import PublicKeyRing
from user import getUserDataByEmail
import rsa
import datetime


class KeyRingManager:
    def __init__(self):
        self.privateKeyRing = PrivateKeyRing()
        self.publicKeyRing = PublicKeyRing()

    def generateNewPairRSA(self, keySize: int, userID: str, password: str):
        user = getUserDataByEmail(userID)
        if user is not None:
            if user.checkPassword(password=password):
                pu, pr = rsa.newkeys(keySize)
                self.publicKeyRing.addToRing(datetime.datetime.now(), pu, userID)
                self.privateKeyRing.addToRing(datetime.datetime.now(), pu, pr, userID)
            else:
                pass  # todo
        else:
            pass  # todo

    def getPU(self, keyID: int):
        return self.publicKeyRing.getPU(keyID=keyID)

    def getPR(self, keyID: int, password: str):
        return self.privateKeyRing.getPR(keyID=keyID, password=password)
