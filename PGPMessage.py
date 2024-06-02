from base64 import b64encode, b64decode
from datetime import datetime
import zlib

from Cryptodome.PublicKey import RSA
from RSAwrapper import RSA_Algo
from RSAwrapper import RSA
from TripleDES import TripleDES
from AES128 import AES128
from chardet import detect
import json


class PGPMessage:
    def __init__(self, timestamp: datetime = None, data: str = None):
        self.message = {'timestamp': timestamp, 'data': data}
        self.signature = {}
        self.operations = {
            'encryption': 0,
            'authentication': False,
            'compression': False
        }
        self.PGPMessage = {}

    def save(self, filePath: str, PU: RSA.RsaKey | None, PR: RSA.RsaKey | None, isCompressed: bool, algo: int,
             keyID: int):

        self.message['timestamp'] = self.message['timestamp'].isoformat() if self.message[
                                                                                 'timestamp'] is not None else None

        if PR is not None:
            self.signature = {
                'messageDigest': b64encode(RSA_Algo.sign(PR, self.message['data'].encode('utf-8'))).decode('utf-8'),
                'timestamp': datetime.now().isoformat(),
                'senderKeyID': keyID}
            self.operations['authentication'] = True
        if PU is not None:
            messageAndSignature = {
                'signature': self.signature,
                'message': self.message
            }

            messageAndSignatureEncrypted = None

            if isCompressed:
                messageAndSignatureEncrypted = b64encode(
                    zlib.compress(json.dumps(messageAndSignature).encode('utf-8'))).decode('utf-8')
                self.operations['compression'] = True
            if algo == 1:
                key = TripleDES.generateKey()
                messageAndSignatureEncrypted = TripleDES.encrypt(
                    json.dumps(messageAndSignature) if not isCompressed else messageAndSignatureEncrypted,
                    key
                )
                self.operations['encryption'] = 1
            else:
                key = AES128.generateKey()
                messageAndSignatureEncrypted = AES128.encrypt(
                    json.dumps(messageAndSignature) if not isCompressed else messageAndSignatureEncrypted,
                    key
                )
                self.operations['encryption'] = 2
            self.PGPMessage['messageAndSignatureEncrypted'] = json.dumps(messageAndSignatureEncrypted)
            self.PGPMessage['sessionKey'] = b64encode(RSA_Algo.encrypt(PU, key)).decode('utf-8')
            self.PGPMessage['recipientKeyID'] = PU.n % 2 ** 64
        else:
            if self.signature:
                self.PGPMessage['signature'] = self.signature
            if isCompressed:
                self.PGPMessage['message'] = b64encode(zlib.compress(json.dumps(self.message).encode('utf-8'))).decode(
                    'utf-8')
                self.operations['compression'] = True
            else:
                self.PGPMessage['message'] = self.message
        self.PGPMessage['operations'] = self.operations
        with open(filePath, 'w') as f:
            json.dump(self.PGPMessage, f)

    def load(self, filePath: str, PR: RSA.RsaKey, PU: RSA.RsaKey):
        with open(filePath, 'r') as f:
            self.PGPMessage = json.load(f)
        if self.PGPMessage['operations']['encryption'] != 0:
            self.PGPMessage['messageAndSignatureEncrypted'] = json.loads(
                self.PGPMessage['messageAndSignatureEncrypted'])
            self.operations = self.PGPMessage['operations']

            temp = None

            if self.operations['encryption'] == 1:
                key = RSA_Algo.decrypt(PR, b64decode(self.PGPMessage['sessionKey'].encode('utf-8')))
                temp = TripleDES.decrypt(self.PGPMessage['messageAndSignatureEncrypted']['ciphertext'].encode('utf-8'),
                                         self.PGPMessage['messageAndSignatureEncrypted']['iv'].encode('utf-8'),
                                         key)

            elif self.operations['encryption'] == 2:
                key = RSA_Algo.decrypt(PR, b64decode(self.PGPMessage['sessionKey'].encode('utf-8')))
                temp = AES128.decrypt(self.PGPMessage['messageAndSignatureEncrypted']['ciphertext'].encode('utf-8'),
                                      self.PGPMessage['messageAndSignatureEncrypted']['iv'].encode('utf-8'),
                                      key)

            if self.operations['compression']:
                temp = json.loads(zlib.decompress(b64decode(temp.encode('utf-8'))).decode('utf-8'))
            else:
                temp = json.loads(temp)

            if temp['signature'] and not RSA_Algo.verify(PU, temp['message']['data'].encode('utf-8'),
                                                         b64decode(
                                                             temp['signature']['messageDigest'].encode('utf-8'))):
                pass  # to do
            else:
                self.message = temp['message']
                self.signature = temp['signature']
        elif self.PGPMessage['operations']['authentication']:
            if self.PGPMessage['operations']['compression']:
                self.message = json.loads(
                    zlib.decompress(b64decode(self.PGPMessage['message'].encode('utf-8'))).decode('utf-8'))
            else:
                self.message = self.PGPMessage['message']
            self.message['timestamp'] = datetime.fromisoformat(self.message['timestamp'])
            if not RSA_Algo.verify(PU, self.message['data'].encode('utf-8'),
                                   b64decode(self.PGPMessage['signature']['messageDigest'].encode('utf-8'))):
                pass  # to do
            else:
                self.signature = self.PGPMessage['signature']
