import base64
import asn1
from datetime import datetime, timezone
import os
from typing import List

'''
Пример использования:
der_data = b'...'  # ваши DER-данные
pem_data = bytes_to_pem(der_data, "CERTIFICATE")
with open('output.pem', 'w') as f:
    f.write(pem_data)
'''
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

def _tbsCertificate_encode(version: int, rdn_bytes: bytes, algid_bytes: bytes, 
                beg_date: datetime, end_date: datetime,
                subjectPKinfo_der: bytes,
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
    serial_num = int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF
    encode.write(serial_num, asn1.Numbers.Integer)

    # signature AlgorithmIdentifier SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode._emit(algid_bytes) # encode.write(algid_bytes, asn1.Numbers.OctetString)
    encode.leave()

    # issuer rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # Validity SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode.write(beg_date.strftime("%y%m%d%H%M%SZ"), asn1.Numbers.UTCTime)
    encode.write(end_date.strftime("%y%m%d%H%M%SZ"), asn1.Numbers.UTCTime)
    encode.leave()

    # subject rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # SubjectPublicKeyInfo SEQUENCE
    encode._emit(subjectPKinfo_der) # encode.write(subjectPKinfo_der, asn1.Numbers.OctetString)

    # extensions
    encode.enter(nr=3, cls=asn1.Classes.Context)    # extensions Context
    encode.enter(asn1.Numbers.Sequence)             # extensions SEQUENCE
    for attr_bytes in attr_bytes_list:
        encode._emit(attr_bytes)
    encode.leave()  # out extensions SEQUENCE
    encode.leave()  # out extensions Context

    encode.leave()  # out tbsCertificate
    

    tbs_bytes = encode.output()
    return tbs_bytes

def _certificate_encode(tbsCert_bytes: bytes):
    encode = asn1.Encoder()
    encode.start()
    encode.enter(asn1.Numbers.Sequence)  # Certificate SEQUENCE
    encode._emit(tbsCert_bytes)
    encode.leave()  # out Certificate
    cert_bytes = encode.output()
    return cert_bytes

''' Создает сертификат на основе запроса на сертификат
Example:
with open('./csr/full.p10', 'r') as pem_file:
    pem_csr = pem_file.read()
cert_bytes = create_cert(pem_csr)
with open('res.pem', 'w') as f:
    f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))
'''
def create_cert(pem_csr: str) -> bytes:
    # Удаляем лишние символы и декодируем Base64
    pem_lines = [line.strip() for line in pem_csr.split('\n') if line.strip()]
    pem_body = ''.join(pem_lines[1:-1])  # Убираем BEGIN/END строки
    der_csr = base64.b64decode(pem_body)

    decoder = asn1.Decoder()
    decoder.start(der_csr)
    decoder.enter()     # CertificationRequest
    decoder.enter()     # certificationRequestInfo

    version = decoder.read()
    # print(f"Version: {version}")

    rdn_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
    decoder.read()

    # SubjectPublicKeyInfo
    subjectPKinfo_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
    decoder.enter() # SubjectPublicKeyInfo
    decoder.enter() # AlgorithmIdentifier
    AlgorithmId_der = _block_to_raw_bytes(der_csr[decoder._get_current_position():])
    decoder.read()  # algorithm
    decoder.read()  # parametrs
    decoder.leave() # out AlgorithmIdentifier
    decoder.read()  # subjectPublicKey
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

    tbsCertificate_bytes = _tbsCertificate_encode(version[1], rdn_der, AlgorithmId_der, 
                            datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc), datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc), 
                            subjectPKinfo_der,
                            attr_bytes_list)
    
    # TODO передавть на подпись tbsCertificate_bytes
    cert_bytes = _certificate_encode(tbsCertificate_bytes)
    
    return cert_bytes