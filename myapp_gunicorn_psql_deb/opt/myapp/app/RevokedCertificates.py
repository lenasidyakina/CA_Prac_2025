from datetime import datetime

class RevokedCertificates:
    def __init__(self, serialNumber: int, revocationDate: datetime, crlEntryExtensions: list=[]):
        self.serialNumber = serialNumber
        self.revocationDate = revocationDate
        self.crlEntryExtensions = crlEntryExtensions    # пока не используется