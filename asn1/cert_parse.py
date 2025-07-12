import asn1
from datetime import datetime
from typing import List, Tuple

from asn1_parse import pem_to_bytes, tbsCertificate_encode, rdn_encode, \
    block_to_raw_bytes, block_length, DATETIME_FORMAT
from models.paramsSelfSignedCert import ParamsSelfSignedCert
from models.RevokedCertificates import RevokedCertificates
from models.RootCert import RootCert
from models.AlgParams import ALL_ALG_PARAMS
from bicry.bicry import BicryWrapper


class CertsAsn1:
    def __init__(self, rootCert: RootCert =None):
        self.rootCert = rootCert
        if rootCert is None:
            alg_type = "b"
        else: 
            alg_type = rootCert.alg_type
        print(f"alg_type = {alg_type}")
        # TODO где то здесь функция проверки что открытый ключ rootCert соответствует закрытом ключу
        self.bicrypt = BicryWrapper(param=ord(alg_type), lib_path='libbicry_openkey.so')
        self.algParams = ALL_ALG_PARAMS[alg_type]

    '''Создает самопоодписанный сертификат  на основе ParamsSelfSignedCert.get_list.get_list()
    return самоподписанный сертификат, открытый ключ, пароль'''
    def create_selfsigned_cert(self, params: ParamsSelfSignedCert, serial_num: int) -> Tuple[bytes, bytes, str]:
        version = 2
        rdn_bytes = rdn_encode(params.paramsRDN)
        public_key = self.bicrypt.generate_keypair("Ivanov")   
        tbsCertificate_bytes = tbsCertificate_encode(
            serial_num=serial_num, version=version, 
            issuer_rdn_bytes=rdn_bytes, 
            subject_rdn_bytes=rdn_bytes,
            sign_algid_bytes=self._signAlgId_encode(),
            beg_date=params.beg_validity_date, end_date=params.end_validity_date,
            subjectPKinfo_bytes=self._subjPKInfo_encode(public_key),
            attr_bytes_list=[]
        )

        signature_bytes = self.bicrypt.electronic_signature(tbsCertificate_bytes)
        cert_bytes = self._signature_encode(
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        password, private_key = self.bicrypt.get_private_key_with_password()
        
        self.rootCert = RootCert(serial_num=serial_num,
                                 issuer_rdn_bytes=rdn_bytes,
                                 alg_type=params.alg_type,
                                 beg_validity_date=params.beg_validity_date, 
                                 end_validity_date=params.end_validity_date,
                                 public_key=public_key)
        return cert_bytes, private_key, password
    
    ''' Создает сертификат на основе запроса на сертификат'''
    def create_cert(self, serial_num: int, 
                    beg_validity_date: datetime, end_validity_date: datetime, 
                    pem_csr: str) -> bytes:
        if self.rootCert is None:
            raise Exception("no root cert created")
        der_csr = pem_to_bytes(pem_csr)

        decoder = asn1.Decoder()
        decoder.start(der_csr)
        decoder.enter()     # CertificationRequest
        decoder.enter()     # certificationRequestInfo

        decoder.read()  # version
        version = 2     # when extensions are used, as expected in this profile (rfc5280), version MUST be 3 (value is 2)

        subject_rdn_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()

        # SubjectPublicKeyInfo
        subjectPKinfo_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()

        # AttributeValue  SEQUENCE
        attr_bytes_list = [] # список блококов байт из которых состоял AttributeValue  SEQUENCE
        decoder.enter() # Attributes [?]
        decoder.enter() # Attributes SEQUENCE
        _, v = decoder.read()   # AttributeType
        assert v == '1.2.840.113549.1.9.14' # стандарт поддерживаемых атрибутов
        decoder.enter() # values SET
        len_attrValue = block_length(der_csr[decoder._get_current_position():])
        decoder.enter() # AttributeValue  SEQUENCE
        start_pos = decoder._get_current_position()
        while decoder._get_current_position() - start_pos < len_attrValue:
            attr_bytes = block_to_raw_bytes(der_csr[decoder._get_current_position():])
            attr_bytes_list.append(attr_bytes)
            t, v = decoder.read()

        # TODO Получить данные о ЦС и вставить из в extentoins: добавить в attr_bytes_list
        decoder.leave() # out AttributeValue  SEQUENCE
        decoder.leave() # out values SET
        decoder.leave() # out Attributes SEQUENCE
        decoder.leave() # out Attributes [?]

        decoder.leave() # out certificationRequestInfo

        tbsCertificate_bytes = tbsCertificate_encode(
            serial_num=serial_num, version=version, 
            issuer_rdn_bytes=self.rootCert.issuer_rdn_bytes, 
            subject_rdn_bytes=subject_rdn_der,
            sign_algid_bytes=self._signAlgId_encode(),
            beg_date=beg_validity_date, end_date=end_validity_date,
            subjectPKinfo_bytes=subjectPKinfo_der,
            attr_bytes_list=attr_bytes_list
        )

        signature_bytes = self.bicrypt.electronic_signature(tbsCertificate_bytes)
        cert_bytes = self._signature_encode(
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        return cert_bytes

    '''Создает подписанный список отозванных сертификатов'''
    def create_crl(self, revokedCerts: List[RevokedCertificates], 
                thisUpdate: datetime, nextUpdate: datetime) -> bytes:
        if self.rootCert is None:
            raise Exception("no root cert created")
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # TBSCertList 

        version = 1
        encoder.write(version, asn1.Numbers.Integer) 

        encoder.enter(asn1.Numbers.Sequence)    # AlgorithmIdentifier
        encoder._emit(self._signAlgId_encode())
        encoder.leave()                         # out AlgorithmIdentifier   

        issuer_rdn_bytes = self.rootCert.issuer_rdn_bytes
        encoder._emit(issuer_rdn_bytes)

        encoder.write(thisUpdate.strftime(DATETIME_FORMAT), asn1.Numbers.UTCTime)
        encoder.write(nextUpdate.strftime(DATETIME_FORMAT), asn1.Numbers.UTCTime)

        # revokedCertificates
        encoder.enter(asn1.Numbers.Sequence)    # revokedCertificates
        for rcert in revokedCerts:
            encoder.enter(asn1.Numbers.Sequence)
            encoder.write(rcert.serialNumber, asn1.Numbers.Integer)
            encoder.write(rcert.revocationDate.strftime(DATETIME_FORMAT), asn1.Numbers.UTCTime)
            # TODO crlEntryExtensions
            encoder.leave() 
        encoder.leave()                         # out revokedCertificates  
        # TODO crlExtensions           
        
        encoder.leave()                         # out TBSCertList   
        
        tbsCertList_bytes = encoder.output()
        signature_bytes = self.bicrypt.electronic_signature(tbsCertList_bytes)
        crl_bytes = self._signature_encode(
            tbs_bytes=tbsCertList_bytes, 
            signature_bytes=signature_bytes)

        return crl_bytes

    def _signature_encode(self, tbs_bytes: bytes, signature_bytes: bytes):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Certificate SEQUENCE
        encoder._emit(tbs_bytes)
        encoder._emit(self._signAlgId_encode())
        encoder.write(signature_bytes, asn1.Numbers.BitString)
        encoder.leave()                         # out Certificate
        cert_bytes = encoder.output()
        return cert_bytes

    def _signAlgId_encode(self):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.algParams.signAlgId, asn1.Numbers.ObjectIdentifier)  
        encoder.leave()
        alg_bytes = encoder.output()
        return alg_bytes
    
    def _subjPKInfo_encode(self, public_key: bytes):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # SubjectPublicKeyInfo
        encoder.enter(asn1.Numbers.Sequence)    # AlgorithmIdentifier
        encoder.write(self.algParams.subjPKAlgId, asn1.Numbers.ObjectIdentifier)  
        encoder.enter(asn1.Numbers.Sequence)    # params
        encoder.write(self.algParams.subjPKAlgIdParam1, asn1.Numbers.ObjectIdentifier)  
        encoder.write(self.algParams.subjPKAlgIdParam2, asn1.Numbers.ObjectIdentifier) 
        encoder.leave()                         # out params
        encoder.leave()                         # out AlgorithmIdentifier
        encoderPK = asn1.Encoder()
        encoderPK.start()
        encoderPK.write(public_key, asn1.Numbers.OctetString)  
        subjectPK_der = encoderPK.output() 
        encoder.write(subjectPK_der, asn1.Numbers.BitString)
        encoder.leave()                         # out SubjectPublicKeyInfo
        alg_bytes = encoder.output()
        return alg_bytes
