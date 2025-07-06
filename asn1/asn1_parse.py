from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import argparse

"""
pem_file = './csr/1.p10'
der_file = './csr/1.der'
pem_csr_to_der(pem_file, der_file)
"""
def pem_csr_to_der(pem_file_path, der_file_path):
    # Чтение PEM-файла
    with open(pem_file_path, 'rb') as pem_file:
        pem_data = pem_file.read()

    # Загрузка CSR (PKCS#10)
    csr = x509.load_pem_x509_csr(pem_data, default_backend())
    
    # Конвертация в DER
    der_data = csr.public_bytes(serialization.Encoding.DER)
    
    # Сохранение DER-файла
    with open(der_file_path, 'wb') as der_file:
        der_file.write(der_data)
    
    print(f"CSR успешно конвертирован в DER: {der_file_path}")


import asn1

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