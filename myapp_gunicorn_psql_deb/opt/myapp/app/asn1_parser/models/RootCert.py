from datetime import datetime
import asn1

from .AlgParams import ALL_ALG_PARAMS, AlgTypes
from ..asn1_parse import block_to_raw_bytes, UTC_DATETIME_FORMAT

class RootCert:
    _instance = None  # Классовый атрибут для хранения экземпляра

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls.instance = super(RootCert, cls).__new__(cls)
        return cls.instance

    '''при повторной инициализации будет перезапись атрибутов во всех экземплярах
    т к RootCert может быть только один'''
    def __init__(self, serial_num: int, issuer_rdn_bytes: bytes, alg_type: AlgTypes,
                 beg_validity_date: datetime, end_validity_date: datetime,
                 public_key: bytes, cert_bytes: bytes):
        self.serial_num = serial_num
        self.issuer_rdn_bytes = issuer_rdn_bytes
        self.alg_type = alg_type
        self.beg_validity_date = beg_validity_date
        self.end_validity_date = end_validity_date
        self.public_key = public_key
        self.cert_bytes = cert_bytes
        self.password = None
        self.private_key = None

    def __str__(self):
        res = f"RootCert:\n"
        res += f"\t serial_num={self.serial_num}\n"
        res += f"\t alg_type={self.alg_type}\n"
        res += f"\t beg_validity_date={self.beg_validity_date}\n"
        res += f"\t end_validity_date={self.end_validity_date}\n"
        return res

def restore_root_cert(cert_bytes: bytes) -> RootCert:
    decoder = asn1.Decoder()
    decoder.start(cert_bytes)
    decoder.enter()         # Certificate SEQUENCE
    decoder.enter()         # TBSCertificate
    _, version = decoder.read()  
    _, serial_num = decoder.read()

    decoder.enter()         # signature AlgorithmIdentifier
    # signAlgId = decoder.read()[-1][-1]
    signAlgId = decoder.read()[-1]
    decoder.leave()         # out signature AlgorithmIdentifier

    issuer_rdn_der = block_to_raw_bytes(cert_bytes[decoder._get_current_position():])
    decoder.read()

    decoder.enter()         # validity
    beg_validity_date = datetime.strptime(decoder.read()[-1], UTC_DATETIME_FORMAT) 
    end_validity_date = datetime.strptime(decoder.read()[-1], UTC_DATETIME_FORMAT) 
    decoder.leave()         # out  validity
    if datetime.now() > end_validity_date:
        # e = 
        raise Exception(f"end validity time of root cert: {beg_validity_date}---{end_validity_date}")

    subject_rdn_der = block_to_raw_bytes(cert_bytes[decoder._get_current_position():])
    decoder.read()
    assert subject_rdn_der == issuer_rdn_der

    decoder.enter()         # subjectPKinfo
    # decoder.read()  # AlgId
    decoder.enter() # AlgId
    decoder.read()
    decoder.enter() # params
    subjPKAlgIdParam1 = decoder.read()[-1]  # subjPKAlgIdParam1
    alg_type = None
    for char_alg, params_alg in ALL_ALG_PARAMS.items():
        if params_alg.signAlgId == signAlgId and params_alg.subjPKAlgIdParam1 == subjPKAlgIdParam1:
            alg_type = char_alg
            break
    if alg_type is None:
        e = f"unknown signature algorithm: {signAlgId}"
        raise Exception(e)
    decoder.read()  # subjPKAlgIdParam2
    decoder.leave() # out params
    decoder.leave() # out AlgId
    decoderPK = asn1.Decoder()
    decoderPK.start(decoder.read()[-1])
    public_key = decoderPK.read()[-1]
    decoder.leave()         # out subjectPKinfo

    decoder.read()  # extentions
    decoder.leave()         # out  TBSCertificate
    decoder.leave()         # out Certificate SEQUENCE

    return RootCert(serial_num=serial_num,
                    issuer_rdn_bytes=issuer_rdn_der,
                    alg_type=alg_type,
                    beg_validity_date=beg_validity_date, end_validity_date=end_validity_date,
                    public_key=public_key, cert_bytes=cert_bytes)
