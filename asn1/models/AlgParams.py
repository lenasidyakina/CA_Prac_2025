

class AlgParams:
    def __init__(self, signAlgId : str, subjPKAlgId : str, 
                 subjPKAlgIdParam1 : str, subjPKAlgIdParam2 : str):
        self.signAlgId = signAlgId
        self.subjPKAlgId = subjPKAlgId
        self.subjPKAlgIdParam1 = subjPKAlgIdParam1
        self.subjPKAlgIdParam2 = subjPKAlgIdParam2

ALL_ALG_PARAMS = {
    "b" : AlgParams(
        signAlgId="1.2.643.7.1.1.3.2",          # gost2012Signature256 (GOST R 34.10-2012 256 bit signature)
        subjPKAlgId="1.2.643.7.1.1.1.1",        # gost2012PublicKey256 (GOST R 34.10-2012 256 bit public key)
        subjPKAlgIdParam1="1.2.643.2.2.35.2",    # cryptoProSignB (CryptoPro ell.curve B for GOST R 34.10-2001)
        subjPKAlgIdParam2="1.2.643.7.1.1.2.2"   # gost2012Digest256 (GOST R 34.11-2012 256 bit digest)
    ),
}
