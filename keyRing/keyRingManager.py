import base64
import hashlib

from keyRing.privateKeyRing import PrivateKeyRing
from keyRing.publicKeyRing import PublicKeyRing
from user import getUserDataByEmail
from Cryptodome.PublicKey import RSA
import datetime
from base64 import b64encode, b64decode


def loadKey(filepath: str, password: str = None):
    if password is None:
        file = open(filepath, "r")
        key_string = file.read()
        file.close()
        return RSA.import_key(b64decode(key_string))
    else:
        file = open(filepath, "r")
        key_string = file.read()
        file.close()
        return RSA.import_key(extern_key=b64decode(key_string.encode('utf-8')), passphrase=hashlib.sha1(base64.b64encode(password.encode('ascii'))).hexdigest())


def saveKey(filepath: str, userID: str, key: RSA.RsaKey, password: str = None):
    user = getUserDataByEmail(userID)
    if user is not None:
        if not key.has_private():
            pu = key.export_key(format='PEM')
            with open(filepath, "w") as file:
                file.write(b64encode(pu).decode('utf-8'))
        else:
            if password is not None and user.checkPassword(password):
                pr = key.export_key(format='PEM', passphrase=user.password)
                with open(filepath, "w") as file:
                    file.write(b64encode(pr).decode('utf-8'))
            else:
                return None


class KeyRingManager:
    def __init__(self):
        self.privateKeyRing = PrivateKeyRing()
        self.publicKeyRing = PublicKeyRing()

    def generateNewPairRSA(self, keySize: int, userID: str, password: str) -> int | None:
        user = getUserDataByEmail(userID)
        if user is not None:
            if user.checkPassword(password=password):
                pr = RSA.generate(keySize)
                pu = pr.public_key()
                self.publicKeyRing.addToRing(datetime.datetime.now(), pu, userID)
                self.privateKeyRing.addToRing(datetime.datetime.now(), pu, pr, userID)
                return pu.n % 2 ** 64
            else:
                pass  # todo
            return None
        else:
            pass  # todo
            return None

    def getPU(self, keyID: int):
        return self.publicKeyRing.getPU(keyID=keyID)

    def getPR(self, keyID: int, password: str):
        return self.privateKeyRing.getPR(keyID=keyID, password=password)

    def deleteKeyPairByKeyID(self, keyID: int, userID: str, password: str):
        user = getUserDataByEmail(userID)
        if user is not None:
            if user.checkPassword(password=password):
                self.privateKeyRing.deleteKey(keyID, userID)
                self.publicKeyRing.deleteKey(keyID, userID)
            else:
                pass  # todo
        else:
            pass  # todo

    def importKey_s(self, filepath: str, userID: str = None, password: str = None):
        key = loadKey(filepath=filepath, password=password)
        if key is None:
            return None
        if self.publicKeyRing.getPU(key.n % 2 ** 64) is not None or self.privateKeyRing.getPR(key.n % 2 ** 64,
                                                                                              password) is not None:
            return -1
        if key.has_private():
            pu_key = key.public_key()
            self.privateKeyRing.addToRing(timestamp=datetime.datetime.now(), PU=pu_key, PR=key, userID=userID)
            self.publicKeyRing.addToRing(timestamp=datetime.datetime.now(), PU=pu_key, userID=userID)
        else:
            self.publicKeyRing.addToRing(timestamp=datetime.datetime.now(), PU=key, userID=userID)
        return key.n % 2 ** 64

    def getAllPrivateKeysByUserID(self, userID):
        return self.privateKeyRing.getAllPrivateKeysByUserID(userID)

    def getAllPublicKeysByUserID(self, userID):
        return self.publicKeyRing.getAllPublicKeysByUserID(userID)
