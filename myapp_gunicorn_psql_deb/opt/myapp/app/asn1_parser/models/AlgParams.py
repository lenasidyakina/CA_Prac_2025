import enum

class AlgParams:
    def __init__(self, signAlgId : str, subjPKAlgId : str, 
                 subjPKAlgIdParam1 : str, subjPKAlgIdParam2 : str):
        self.signAlgId = signAlgId
        self.subjPKAlgId = subjPKAlgId
        self.subjPKAlgIdParam1 = subjPKAlgIdParam1
        self.subjPKAlgIdParam2 = subjPKAlgIdParam2

class AlgTypes(enum.Enum):
    a = 97
    b = 98
    c = 99
    A = 65
    B = 66
    C = 67
    D = 68

ALL_ALG_PARAMS = {
    AlgTypes.a : AlgParams(
        signAlgId="1.2.643.7.1.1.3.2",          # gost2012Signature256 (GOST R 34.10-2012 256 bit signature)
        subjPKAlgId="1.2.643.7.1.1.1.1",        # gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.1",   # cryptoProSignA (CryptoPro ell.curve A for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.7.1.1.2.2"   # gost2012Digest256 (GOST R 34.11-2012 256 bit digest)
    ),
    AlgTypes.b : AlgParams(
        signAlgId="1.2.643.7.1.1.3.2",          # gost2012Signature256 (GOST R 34.10-2012 256 bit signature)
        subjPKAlgId="1.2.643.7.1.1.1.1",        # gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.2",    # cryptoProSignB (CryptoPro ell.curve B for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.7.1.1.2.2"   # gost2012Digest256 (GOST R 34.11-2012 256 bit digest)
    ),
    AlgTypes.c : AlgParams(
        signAlgId="1.2.643.7.1.1.3.2",          # gost2012Signature256 (GOST R 34.10-2012 256 bit signature)
        subjPKAlgId="1.2.643.7.1.1.1.1",        # gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.3",   # cryptoProSignC (CryptoPro ell.curve C for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.7.1.1.2.2"   # gost2012Digest256 (GOST R 34.11-2012 256 bit digest)
    ),
    AlgTypes.A : AlgParams(
        signAlgId="1.2.643.2.2.3",              # gostSignature (GOST R 34.10-2001 + GOST R 34.11-94 signature)
        subjPKAlgId="1.2.643.2.2.19",           # gostPublicKey (GOST R 34.10-2001 (ECC) public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.1",   # cryptoProSignA (CryptoPro ell.curve A for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.2.2.30.1"    # cryptoProDigestA (CryptoPro digest params A (default, variant 'Verba-O') for GOST R 34.11-94)
    ),
    AlgTypes.B : AlgParams(
        signAlgId="1.2.643.2.2.3",              # gostSignature (GOST R 34.10-2001 + GOST R 34.11-94 signature)
        subjPKAlgId="1.2.643.2.2.19",           # gostPublicKey (GOST R 34.10-2001 (ECC) public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.2",   # cryptoProSignB (CryptoPro ell.curve B for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.2.2.30.1"    # cryptoProDigestA (CryptoPro digest params A (default, variant 'Verba-O') for GOST R 34.11-94)
    ),
    AlgTypes.C : AlgParams(
        signAlgId="1.2.643.2.2.3",              # gostSignature (GOST R 34.10-2001 + GOST R 34.11-94 signature)
        subjPKAlgId="1.2.643.2.2.19",           # gostPublicKey (GOST R 34.10-2001 (ECC) public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.3",   # cryptoProSignC (CryptoPro ell.curve C for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.2.2.30.1"    # cryptoProDigestA (CryptoPro digest params A (default, variant 'Verba-O') for GOST R 34.11-94)
    ),
    AlgTypes.D : AlgParams(
        signAlgId="1.2.643.7.1.1.3.2",              # gost2012Signature256 (GOST R 34.10-2012 256 bit signature)
        subjPKAlgId="1.2.643.7.1.1.1.1",            # gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
        subjPKAlgIdParam1="1.2.643.7.1.2.1.1.1",    # cryptoPro2012Sign256A (CryptoPro ell.curve A for GOST R 34.10-2012 256 bit)
        subjPKAlgIdParam2="1.2.643.7.1.1.2.2"       # gost2012Digest256 (GOST R 34.11-2012 256 bit digest)
    ),
}


