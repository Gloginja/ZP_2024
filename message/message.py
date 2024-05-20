from datetime import datetime


class Message:
    def __init__(self, filename: str, timestamp: datetime, data: str):
        self.filename = filename
        self.timestamp = timestamp
        self.data = data
