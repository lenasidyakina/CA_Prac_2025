import base64
import asn1
from datetime import datetime, timezone
import os

def bytes_to_pem(der_bytes: bytes, pem_type: str = "CERTIFICATE") -> str:
    b64_data = base64.b64encode(der_bytes).decode('ascii')
    
    # Разбиваем на строки по 64 символа (стандарт PEM)
    b64_lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    b64_body = '\n'.join(b64_lines)

    pem = f"-----BEGIN {pem_type}-----\n{b64_body}\n-----END {pem_type}-----\n"
    return pem

# Пример использования:
# der_data = b'...'  # ваши DER-данные
# pem_data = bytes_to_pem(der_data, "CERTIFICATE")
# with open('output.pem', 'w') as f:
#     f.write(pem_data)


def encode_tag(tag: asn1.Tag, length: int):
    encoder = asn1.Encoder()
    encoder.start()
    # print(f"tag: {tag.nr, tag.typ, tag.cls}")
    # print(f"{tag.nr < 31}, {encoder._encoding == Encoding.DER}, {bytes([tag.nr | tag.typ | tag.cls])}")
    encoder._emit_tag(tag.nr, tag.typ, tag.cls)
    encoder._emit_length(length)
    # print(f"{encoder._stack}")
    return encoder.output() 

def block_to_raw_bytes(data_block: bytes) -> bytes:
    decoder = asn1.Decoder()
    decoder.start(data_block)
    start_pos = decoder._get_current_position()         # Внутренний индекс декодера
    tag_subject = decoder.peek()                        # Получаем только тег без продвижения позиции
    length = decoder._decode_length(tag_subject.typ)    # Полная длина элемента (тег + длина + значение)
    # print(f"length={length}, hex={hex(length)}")

    hex_tag = encode_tag(tag_subject, length).hex()     # переводим в тег (тип + длина (без value))
    len_hex_tag = len(bytes.fromhex(hex_tag))           
    # print(f"{hex_tag}, {len(bytes.fromhex(hex_tag))}")

    raw_bytes = data_block[start_pos:start_pos + length + len_hex_tag]
    return raw_bytes


def cert_encode(version: int, rdn_bytes: bytes, algid_bytes: bytes, 
                beg_date: datetime, end_date: datetime,
                subjectPKinfo_der: bytes) -> bytes:
    encode = asn1.Encoder()
    # version
    encode.start()
    encode.enter(asn1.Numbers.Sequence)  # Certificate SEQUENCE
    encode.enter(asn1.Numbers.Sequence)  # tbsCertificate SEQUENCE
    encode.enter(nr=0, cls=asn1.Classes.Context) 
    encode.write(version, asn1.Numbers.Integer)  # version INTEGER
    encode.leave()

    # serialNumber INTEGER
    serial_num = int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF
    encode.write(serial_num, asn1.Numbers.Integer)

    # signature AlgorithmIdentifier SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode._emit(algid_bytes) # encode.write(algid_bytes, asn1.Numbers.OctetString)
    encode.leave()

    # rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # Validity SEQUENCE
    encode.enter(asn1.Numbers.Sequence)
    encode.write(beg_date.strftime("%y%m%d%H%M%SZ"), asn1.Numbers.UTCTime)
    encode.write(end_date.strftime("%y%m%d%H%M%SZ"), asn1.Numbers.UTCTime)
    encode.leave()

    # rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, asn1.Numbers.OctetString)

    # SubjectPublicKeyInfo SEQUENCE
    encode._emit(subjectPKinfo_der) # encode.write(subjectPKinfo_der, asn1.Numbers.OctetString)

    encode.leave()  # out tbsCertificate
    encode.leave()  # out Certificate

    cert_bytes = encode.output()
    return cert_bytes