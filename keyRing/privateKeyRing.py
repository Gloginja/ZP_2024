import base64
import datetime
import rsa
from Cryptodome.Cipher import CAST
from user import getUserDataByEmail


class PrivateKeyRing:
    def __init__(self):
        self.keyRing = []

    def addToRing(self, timestamp: datetime, PU: rsa.PublicKey, PR: rsa.PrivateKey, userID: str):
        cipher = CAST.new(base64.b64encode(bytearray().extend(map(ord, getUserDataByEmail(userID).password[:16]))), CAST.MODE_OPENPGP)
        encPR = cipher.encrypt(PR.save_pkcs1(format='PEM'))
        self.keyRing.append(
            {'timestamp': timestamp, 'keyID': PU.n % 2 ** 64, 'PU': PU, 'encPR': encPR, 'userID': userID})

    def getPR(self, keyID, password):
        for k in self.keyRing:
            if k['keyID'] == keyID:
                user = getUserDataByEmail(k['userID'])
                if user.checkPassword(password):
                    return rsa.PrivateKey.load_pkcs1(CAST.new(user.password, CAST.MODE_OPENPGP).decrypt(k['encPR']), 'PEM')
                else:
                    return None
        return None

