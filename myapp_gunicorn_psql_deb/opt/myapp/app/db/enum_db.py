import enum

class CRLReasonText(enum.Enum):
    unspecified = "unspecified"
    keyCompromise = "keyCompromise"
    cACompromise = "cACompromise"
    affiliationChanged = "affiliationChanged"
    superseded = "superseded"
    cessationOfOperation = "cessationOfOperation"
    certificateHold = "certificateHold"
    removeFromCRL = "removeFromCRL"