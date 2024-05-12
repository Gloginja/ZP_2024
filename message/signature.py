from datetime import datetime


class Signature:
    def __init__(self, timestamp: datetime, keyIDSender: int, twoOctetsDigest: int, messageDigest):
        self.timestamp = timestamp
        self.keyIDSender = keyIDSender
        self.twoOctetsDigest = twoOctetsDigest
        self.messageDigest = messageDigest
