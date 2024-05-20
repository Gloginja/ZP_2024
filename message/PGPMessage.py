from message.message import Message
from sessionKey import SessionKey
from signature import Signature


class PGPMessage:
    def __init__(self, sessionKey: SessionKey, signature: Signature, message: Message):
        self.sessionKey = sessionKey
        self.signature = signature
        self.message = message
