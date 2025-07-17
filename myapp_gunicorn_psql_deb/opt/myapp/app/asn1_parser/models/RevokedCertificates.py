from datetime import datetime
import enum

# обьяснения и перевода перечисленных причин в стандарте нет
class CRLReasonCode(enum.Enum):
    unspecified = 0
    keyCompromise = 1
    cACompromise = 2
    affiliationChanged = 3
    superseded = 4
    cessationOfOperation = 5
    certificateHold = 6
    removeFromCRL = 8

class RevokedCertificates:
    def __init__(self, serialNumber: int, 
                 revocationDate: datetime, 
                 crlReasonCode: CRLReasonCode):
        self.serialNumber = serialNumber
        self.revocationDate = revocationDate    # Дата отзыва
        self.crlReasonCode = crlReasonCode      # причина отзыва