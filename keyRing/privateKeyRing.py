import base64
import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import CAST
from user import getUserDataByEmail
from base64 import b64encode


class PrivateKeyRing:
    def __init__(self):
        self.keyRing = []

    def addToRing(self, timestamp: datetime, PU: RSA.RsaKey, PR: RSA.RsaKey, userID: str):
        hashedPass = getUserDataByEmail(userID).password
        cipher = CAST.new(hashedPass[:16].encode('utf-8') if len(hashedPass) >= 16 else hashedPass.encode('utf-8'),
                          CAST.MODE_OPENPGP)
        encPR = cipher.encrypt(PR.export_key(format='PEM', passphrase=hashedPass))
        self.keyRing.append(
            {'timestamp': timestamp, 'keyID': PU.n % 2 ** 64, 'PU': PU, 'encPR': encPR, 'userID': userID})

    def getPR(self, keyID, password):
        for k in self.keyRing:
            if k['keyID'] == keyID:
                user = getUserDataByEmail(k['userID'])
                if user.checkPassword(password):
                    eiv = k['encPR'][:CAST.block_size + 2]
                    ciphertext = k['encPR'][CAST.block_size + 2:]
                    cipher = CAST.new(
                        user.password[:16].encode('utf-8') if len(user.password) >= 16 else user.password.encode('utf-8'),
                        CAST.MODE_OPENPGP, eiv)
                    return RSA.import_key(cipher.decrypt(ciphertext), user.password)
                else:
                    return None
        return None

    def deleteKey(self, keyID: int, userID: str) -> bool:
        for k in self.keyRing:
            if k['keyID'] == keyID and k['userID'] == userID:
                self.keyRing.remove(k)
                return True
        return False

    def getAllPrivateKeysByUserID(self, userID: str):
        keys = []
        for k in self.keyRing:
            if k['userID'] == userID:
                keys.append(k)
        return keys
