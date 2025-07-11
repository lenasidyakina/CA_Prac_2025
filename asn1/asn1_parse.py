import base64
import asn1
from datetime import datetime, timezone
import os
from typing import List
from models.paramsSelfSignedCert import ParamsSelfSignedCert
from models.RevokedCertificates import RevokedCertificates
from models.AlgParams import AlgParams, ALL_ALG_PARAMS
from bicry.bicry import BicryWrapper

DATETIME_FORMAT = "%y%m%d%H%M%SZ"

class CertsAsn1:
    def __init__(self):
        self.bicrypt = BicryWrapper()
        self.algParams = ALL_ALG_PARAMS["b"]

    '''Создает самопоодписанный сертификат  на основе ParamsSelfSignedCert.get_list()'''
    def create_selfsigned_cert(self, params: ParamsSelfSignedCert, serial_num: int) -> bytes:
        version = 2
        rdn_bytes = _create_rdn(params)
        # with open('rdn.der', 'wb') as f:
        #     f.write(rdn_bytes)

        sign_alg_bytes = self._signAlgId_encode()
        algSubjectPK_der = self._subjPKAlgId_encode()
        subjectPK_der = self._get_subjectPK()
        tbsCertificate_bytes = _tbsCertificate_encode(
            serial_num=serial_num,
            version=version, issuer_rdn_bytes=rdn_bytes, subject_rdn_bytes=rdn_bytes,
            algid_bytes=sign_alg_bytes,
            beg_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
            end_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
            # subjectPKinfo_der=subjectPKinfo_der,
            algSubjectPK_der=algSubjectPK_der, subjectPK_der=subjectPK_der,
            attr_bytes_list=[]
        )

        # ЭТО ПИЗДЕЦ ----
        with open('./bicry/tbs.der', 'wb') as f:
            f.write(tbsCertificate_bytes)
        self.bicrypt.electronic_signature()
        with open('./signature.bin', 'rb') as f:
            signature_bytes = f.read()
        # ЭТО ПИЗДЕЦ -----
        cert_bytes = self._signature_encode(
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        return cert_bytes
    
    ''' Создает сертификат на основе запроса на сертификат'''
    def create_cert(self, serial_num: int, pem_csr: str) -> bytes:
        # Удаляем лишние символы и декодируем Base64
        pem_lines = [line.strip() for line in pem_csr.split('\n') if line.strip()]
        pem_body = ''.join(pem_lines[1:-1])  # Убираем BEGIN/END строки
        der_csr = base64.b64decode(pem_body)

        decoder = asn1.Decoder()
        decoder.start(der_csr)
        decoder.enter()     # CertificationRequest
        decoder.enter()     # certificationRequestInfo

        # version
        decoder.read()
        # when extensions are used, as expected in this profile (rfc5280), version MUST be 3 (value is 2)
        version = 2

        rdn_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()

        # SubjectPublicKeyInfo
        # subjectPKinfo_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.enter() # SubjectPublicKeyInfo
        algSubjectPK_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.enter() # AlgorithmIdentifier
        AlgorithmId_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()  # algorithm
        decoder.read()  # parametrs
        decoder.leave() # out AlgorithmIdentifier
        # subjectPK_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
        _, v = decoder.read()  # subjectPublicKey
        subjectPK_der = v
        decoder.leave() # out SubjectPublicKeyInfo

        # AttributeValue  SEQUENCE
        attr_bytes_list = [] # список блококов байт из которых состоял AttributeValue  SEQUENCE
        decoder.enter() # Attributes [?]
        decoder.enter() # Attributes SEQUENCE
        t, v = decoder.read()   # AttributeType
        assert v == '1.2.840.113549.1.9.14' # стандарт поддерживаемых атрибутов
        decoder.enter() # values SET
        len_attrValue = _block_length(der_csr[decoder._get_current_position():])
        decoder.enter() # AttributeValue  SEQUENCE
        start_pos = decoder._get_current_position()
        while decoder._get_current_position() - start_pos < len_attrValue:
            attr_bytes = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
            attr_bytes_list.append(attr_bytes)
            t, v = decoder.read()

        # TODO Получить данные о ЦС и вставить из в extentoins: добавить в attr_bytes_list
        decoder.leave() # out AttributeValue  SEQUENCE
        decoder.leave() # out values SET
        decoder.leave() # out Attributes SEQUENCE
        decoder.leave() # out Attributes [?]

        decoder.leave() # out certificationRequestInfo

        tbsCertificate_bytes = _tbsCertificate_encode(
            serial_num=serial_num,
            version=version, issuer_rdn_bytes=rdn_der, subject_rdn_bytes=rdn_der,
            algid_bytes=AlgorithmId_der,
            beg_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
            end_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
            # subjectPKinfo_der=subjectPKinfo_der,
            algSubjectPK_der=algSubjectPK_der, subjectPK_der=subjectPK_der,
            attr_bytes_list=attr_bytes_list
        )
        # ЭТО ПИЗДЕЦ ----
        with open('./bicry/tbs.der', 'wb') as f:
            f.write(tbsCertificate_bytes)
        self.bicrypt.electronic_signature()
        with open('./signature.bin', 'rb') as f:
            signature_bytes = f.read()
        # ЭТО ПИЗДЕЦ -----
        cert_bytes = self._signature_encode(
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        return cert_bytes

    '''Создает подписанный список отозванных сертификатов'''
    def create_crl(self, revokedCerts: List[RevokedCertificates], 
                issuer: ParamsSelfSignedCert, 
                thisUpdate: datetime, nextUpdate: datetime) -> bytes:
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # CertificateList  
        encoder.enter(asn1.Numbers.Sequence)    # TBSCertList 

        version = 1
        encoder.write(version, asn1.Numbers.Integer) 

        encoder.enter(asn1.Numbers.Sequence)    # AlgorithmIdentifier
        # AlgorithmIdentifier is defined in Section 4.1.1.2
        encoder.leave()                         # out AlgorithmIdentifier   

        issuer_rdn_bytes = _create_rdn(issuer)
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
        encoder.leave()                         # out CertificateList  

        crl_bytes = encoder.output()
        return crl_bytes


    def _signature_encode(self, tbs_bytes: bytes, signature_bytes: bytes):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Certificate SEQUENCE
        encoder._emit(tbs_bytes)
        encoder._emit(self._signAlgId_encode())
        encoder.write(signature_bytes, asn1.Numbers.BitString)
        # encoder._emit(signature_bytes)
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

    def _subjPKAlgId_encode(self):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.algParams.subjPKAlgId, asn1.Numbers.ObjectIdentifier)  
        # params
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.algParams.subjPKAlgIdParam1, asn1.Numbers.ObjectIdentifier)  
        encoder.write(self.algParams.subjPKAlgIdParam2, asn1.Numbers.ObjectIdentifier) 
        encoder.leave()
        encoder.leave()
        alg_bytes = encoder.output()
        return alg_bytes

    def _get_subjectPK(self) -> bytes:
        public_key = self.bicrypt.export_public_key("Ivanov")    # Экспортируем ключ для пользователя
        # data_bytes = bytes.fromhex('6b16a8482dcf05afc2c0b5cebcb2af797c7c8efdef528eea151d41d799981f6333db4d9d5205439dcb1dfec7da8461ae432cecb13a80fed8d21c999f3dec6d19') 
        encoder = asn1.Encoder()
        encoder.start()
        encoder.write(public_key, asn1.Numbers.OctetString)  
        subjectPK_der = encoder.output() 
        return subjectPK_der

def generate_serial_num() -> int:
    return int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF

def bytes_to_pem(der_bytes: bytes, pem_type: str = "CERTIFICATE") -> str:
    b64_data = base64.b64encode(der_bytes).decode('ascii')
    
    # Разбиваем на строки по 64 символа (стандарт PEM)
    b64_lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    b64_body = '\n'.join(b64_lines)

    pem = f"-----BEGIN {pem_type}-----\n{b64_body}\n-----END {pem_type}-----\n"
    return pem

def _encode_tag(tag: asn1.Tag, length: int):
    encoder = asn1.Encoder()
    encoder.start()
    # print(f"tag: {tag.nr, tag.typ, tag.cls}")
    # print(f"{tag.nr < 31}, {encoder._encoding == Encoding.DER}, {bytes([tag.nr | tag.typ | tag.cls])}")
    encoder._emit_tag(tag.nr, tag.typ, tag.cls)
    encoder._emit_length(length)
    # print(f"{encoder._stack}")
    return encoder.output() 

def _block_length(data_block: bytes) -> int:
    decoder = asn1.Decoder()
    decoder.start(data_block)
    tag_subject = decoder.peek()                        # Получаем только тег без продвижения позиции
    length = decoder._decode_length(tag_subject.typ)    # Полная длина элемента (тег + длина + значение)
    # print(f"length={length}, hex={hex(length)}")
    return  length

def _block_to_raw_bytes(data_block: bytes) -> bytes:
    decoder = asn1.Decoder()
    decoder.start(data_block)
    start_pos = decoder._get_current_position()         # Внутренний индекс декодера
    tag_subject = decoder.peek()                        # Получаем только тег без продвижения позиции
    length = decoder._decode_length(tag_subject.typ)    # Полная длина элемента (тег + длина + значение)
    # print(f"length={length}, hex={hex(length)}")

    hex_tag = _encode_tag(tag_subject, length).hex()     # переводим в тег (тип + длина (без value))
    len_hex_tag = len(bytes.fromhex(hex_tag))           
    # print(f"{hex_tag}, {len(bytes.fromhex(hex_tag))}")

    raw_bytes = data_block[start_pos:start_pos + length + len_hex_tag]
    return raw_bytes

def _tbsCertificate_encode(serial_num: int, version: int, issuer_rdn_bytes: bytes, subject_rdn_bytes: bytes, 
                algid_bytes: bytes, 
                beg_date: datetime, end_date: datetime,
                algSubjectPK_der: bytes, subjectPK_der: bytes,
                attr_bytes_list: List[bytes]) -> bytes:
    encode = asn1.Encoder()
    encode.start()
    # version
    encode.enter(asn1.Numbers.Sequence)  # tbsCertificate SEQUENCE

    # version INTEGER
    encode.enter(nr=0, cls=asn1.Classes.Context) 
    encode.write(version, asn1.Numbers.Integer)  
    encode.leave()

    # serialNumber INTEGER
    encode.write(serial_num, asn1.Numbers.Integer)

    # signature AlgorithmIdentifier SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode._emit(algid_bytes) # encode.write(algid_bytes, asn1.Numbers.OctetString)
    encode.leave()

    # issuer rdnSequence Name SEQUENCE
    encode._emit(issuer_rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # Validity SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode.write(beg_date.strftime(DATETIME_FORMAT), asn1.Numbers.UTCTime)
    encode.write(end_date.strftime(DATETIME_FORMAT), asn1.Numbers.UTCTime)
    encode.leave()

    # subject rdnSequence Name SEQUENCE
    encode._emit(subject_rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # SubjectPublicKeyInfo SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode._emit(algSubjectPK_der) # encode.write(subjectPKinfo_der, asn1.Numbers.OctetString)\
    # encode._emit(subjectPK_der)
    encode.write(subjectPK_der, asn1.Numbers.BitString)
    encode.leave()

    # extensions
    if len(attr_bytes_list):
        encode.enter(nr=3, cls=asn1.Classes.Context)    # extensions Context
        encode.enter(asn1.Numbers.Sequence)             # extensions SEQUENCE
        for attr_bytes in attr_bytes_list:
            encode._emit(attr_bytes)
        encode.leave()  # out extensions SEQUENCE
        encode.leave()  # out extensions Context

    encode.leave()  # out tbsCertificate
    

    tbs_bytes = encode.output()
    return tbs_bytes





'''Создает rdnSequence Name SEQUENCE на основе ParamsSelfSignedCert.get_list()'''
def _create_rdn(params: ParamsSelfSignedCert) -> bytes:
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)    # rdnSequence
    for p in params.get_list():
        encoder.enter(asn1.Numbers.Set)         # RelativeDistinguishedName
        encoder.enter(asn1.Numbers.Sequence)    # AttributeTypeAndValue
        encoder.write(p[1], asn1.Numbers.ObjectIdentifier)
        encoder.write(p[0], asn1.Numbers.UTF8String)
        encoder.leave()                         # out AttributeTypeAndValue
        encoder.leave()                         # out RelativeDistinguishedName
    encoder.leave()                         # out rdnSequence
    rdn_bytes = encoder.output()
    return rdn_bytes



