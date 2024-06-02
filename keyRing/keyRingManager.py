from keyRing.privateKeyRing import PrivateKeyRing
from keyRing.publicKeyRing import PublicKeyRing
from user import getUserDataByEmail
from Cryptodome.PublicKey import RSA
import datetime
from base64 import b64encode, b64decode


def loadKey(filepath: str, userID: str = None, password: str = None):
    if userID is None or password is None:
        file = open(filepath, "r")
        key_string = file.read()
        file.close()
        return RSA.import_key(b64decode(key_string))
    else:
        if userID is not None:
            user = getUserDataByEmail(userID)
            if user is not None and password is not None and user.checkPassword(password):
                file = open(filepath, "r")
                key_string = file.read()
                file.close()
                return RSA.import_key(extern_key=key_string, passphrase=user.password)
            else:
                return None
        else:
            return None


def saveKey(filepath: str, userID: str, key: RSA.RsaKey, password: str = None):
    user = getUserDataByEmail(userID)
    if user is not None:
        if not key.has_private():
            exp = key.export_key(format='PEM')
            with open(filepath, "w") as file:
                file.write(b64encode(exp).decode('utf-8'))
        else:
            if password is not None and user.checkPassword(password):
                pr = key.export_key(format='PEM', passphrase=user.password)
                pu = key.public_key().export_key(format='PEM')
                combined = pr + pu;
                with open(filepath, "w") as file:
                    file.write(b64encode(combined).decode('utf-8'))
            else:
                pass  # to do


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
