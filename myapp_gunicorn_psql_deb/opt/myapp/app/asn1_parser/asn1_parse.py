import base64
import asn1
from datetime import datetime, timezone
import os
from typing import List
from .models.paramsSelfSignedCert import ParamsRDN, ExtentionsCert
from pyasn1_modules import rfc5280

UTC_DATETIME_FORMAT = "%y%m%d%H%M%SZ"
GENERALIZED_TIME_FORMAT = "%Y%m%d%H%M%SZ"

# def generate_serial_num() -> int:
#     return int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF

def generate_serial_num() -> int:
    random_bytes = os.urandom(36)
    num = int.from_bytes(random_bytes, 'big')
    # Маска для 286 бит: 2^286 - 1
    return num & ((1 << 286) - 1)

def bytes_to_pem(der_bytes: bytes, pem_type: str = "CERTIFICATE") -> str:
    b64_data = base64.b64encode(der_bytes).decode('ascii')
    
    # Разбиваем на строки по 64 символа (стандарт PEM)
    b64_lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    b64_body = '\n'.join(b64_lines)

    pem = f"-----BEGIN {pem_type}-----\n{b64_body}\n-----END {pem_type}-----\n"
    return pem

def pem_to_bytes(pem: str):
     # Удаляем лишние символы и декодируем Base64
    pem_lines = [line.strip() for line in pem.split('\n') if line.strip()]
    pem_body = ''.join(pem_lines[1:-1])  # Убираем BEGIN/END строки
    return base64.b64decode(pem_body)

def _encode_tag(tag: asn1.Tag, length: int):
    encoder = asn1.Encoder()
    encoder.start()
    # print(f"tag: {tag.nr, tag.typ, tag.cls}")
    # print(f"{tag.nr < 31}, {encoder._encoding == Encoding.DER}, {bytes([tag.nr | tag.typ | tag.cls])}")
    encoder._emit_tag(tag.nr, tag.typ, tag.cls)
    encoder._emit_length(length)
    # print(f"{encoder._stack}")
    return encoder.output() 

def block_length(data_block: bytes) -> int:
    decoder = asn1.Decoder()
    decoder.start(data_block)
    tag_subject = decoder.peek()                        # Получаем только тег без продвижения позиции
    length = decoder._decode_length(tag_subject.typ)    # Полная длина элемента (тег + длина + значение)
    # print(f"length={length}, hex={hex(length)}")
    return  length

def block_to_raw_bytes(data_block: bytes) -> bytes:
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

def tbsCertificate_encode(serial_num: int, version: int, issuer_rdn_bytes: bytes, subject_rdn_bytes: bytes, 
                sign_algid_bytes: bytes, 
                beg_date: datetime, end_date: datetime,
                subjectPKinfo_bytes : bytes,
                # algSubjectPK_der: bytes, subjectPK_der: bytes,
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
    # encode.enter(asn1.Numbers.Sequence)
    encode._emit(sign_algid_bytes) # encode.write(algid_bytes, asn1.Numbers.OctetString)
    # encode.leave()

    # issuer rdnSequence Name SEQUENCE
    encode._emit(issuer_rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # Validity SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode.write(beg_date.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)
    encode.write(end_date.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)
    encode.leave()

    # subject rdnSequence Name SEQUENCE
    encode._emit(subject_rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # SubjectPublicKeyInfo SEQUENCE
    encode._emit(subjectPKinfo_bytes)
    # encode.enter(asn1.Numbers.Sequence)
    # encode._emit(algSubjectPK_der) # encode.write(subjectPKinfo_der, asn1.Numbers.OctetString)\
    # # encode._emit(subjectPK_der)
    # encode.write(subjectPK_der, asn1.Numbers.BitString)
    # encode.leave()

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

'''Создает rdnSequence Name SEQUENCE на основе ParamsRDN.get_list()'''
def rdn_encode(params: ParamsRDN) -> bytes:
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

def rdn_decode(rdn_bytes: bytes) -> ParamsRDN:
    decoder = asn1.Decoder()
    decoder.start(rdn_bytes)
    len_rdnSeq = block_length(rdn_bytes[decoder._get_current_position():])

    resRDN = ParamsRDN()
    decoder.enter()         # rdnSequence  SEQUENCE
    start_pos = decoder._get_current_position()
    while decoder._get_current_position() - start_pos < len_rdnSeq:
        decoder.enter() # RelativeDistinguishedName
        decoder.enter() # AttributeTypeAndValue
        type = decoder.read()[-1]
        val = decoder.read()[-1]
        if type not in resRDN.params.keys():
            raise Exception("rdn_decode: unknown oid")
        resRDN.params[type] = val
        decoder.leave() # out AttributeTypeAndValue
        decoder.leave() # out RelativeDistinguishedName
    decoder.leave()         # out rdnSequence  SEQUENCE

    return resRDN

'''
subject_is_CA - является ли subject (для самоподписанного всегда да) сертификата центром сертификации
max_depth_certs - макс число сертификатов которые могут быть в цепочке дальше
'''
def basicConstraints_encode(subject_is_CA: bool, max_depth_certs: int) -> bytes:
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter() # Extention
    encoder.write(str(rfc5280.id_ce_basicConstraints), asn1.Numbers.ObjectIdentifier)
    # critical = false

    val_encoder = asn1.Encoder()
    val_encoder.start()
    val_encoder.enter()
    val_encoder.write(subject_is_CA, asn1.Numbers.Boolean)
    val_encoder.write(max_depth_certs, asn1.Numbers.Integer)
    val_encoder.leave()
    val_bytes = encoder.output()

    encoder.write(val_bytes, asn1.Numbers.OctetString)
    encoder.leave()

    extention_bytes = encoder.output()
    return extention_bytes
