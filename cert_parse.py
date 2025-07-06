import base64
from asn1 import Decoder, Encoder, Numbers, Classes
from asn1_parse import *
import os
from datetime import datetime, timezone

pem_file_path = './csr/full.p10'
with open(pem_file_path, 'r') as pem_file:
    pem_csr = pem_file.read()

# Удаляем лишние символы и декодируем Base64
pem_lines = [line.strip() for line in pem_csr.split('\n') if line.strip()]
pem_body = ''.join(pem_lines[1:-1])  # Убираем BEGIN/END строки
der_csr = base64.b64decode(pem_body)
# subjectPKinfo_bytes
def cert_encode(version: int, rdn_bytes: bytes, algid_bytes: bytes, 
                beg_date: datetime, end_date: datetime,
                subjectPKinfo_der: bytes) -> bytes:
    encode = Encoder()
    # version
    encode.start()
    encode.enter(Numbers.Sequence)  # Certificate SEQUENCE
    encode.enter(Numbers.Sequence)  # tbsCertificate SEQUENCE
    encode.enter(nr=0, cls=Classes.Context) 
    encode.write(version, Numbers.Integer)  # version INTEGER
    encode.leave()

    # serialNumber INTEGER
    serial_num = int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF
    encode.write(serial_num, Numbers.Integer)

    # signature AlgorithmIdentifier SEQUENCE
    encode.enter(Numbers.Sequence)
    encode._emit(algid_bytes) # encode.write(algid_bytes, Numbers.OctetString)
    encode.leave()

    # rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, Numbers.OctetString)

    # Validity SEQUENCE
    encode.enter(Numbers.Sequence)
    encode.write(beg_date.strftime("%y%m%d%H%M%SZ"), Numbers.UTCTime)
    encode.write(end_date.strftime("%y%m%d%H%M%SZ"), Numbers.UTCTime)
    encode.leave()

    # rdnSequence Name SEQUENCE
    encode._emit(rdn_bytes) # encode.write(rdn_bytes, Numbers.OctetString)

    # SubjectPublicKeyInfo SEQUENCE
    encode._emit(subjectPKinfo_der) # encode.write(subjectPKinfo_der, Numbers.OctetString)

    encode.leave()  # out tbsCertificate
    encode.leave()  # out Certificate

    cert_bytes = encode.output()
    return cert_bytes

decoder = Decoder()
decoder.start(der_csr)
decoder.enter()     # CertificationRequest
decoder.enter()     # certificationRequestInfo

version = decoder.read()
# print(f"Version: {version}")

rdn_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
decoder.read()

# SubjectPublicKeyInfo
subjectPKinfo_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
decoder.enter() # SubjectPublicKeyInfo
decoder.enter() # AlgorithmIdentifier
AlgorithmId_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
t, v = decoder.read()  # algorithm
# print(t, v)
decoder.read()  # parametrs
decoder.leave() # out AlgorithmIdentifier
decoder.read()  # subjectPublicKey
decoder.leave() # out SubjectPublicKeyInfo

# t, v = decoder.read()
# print(t, v)

raw_bytes = cert_encode(version[1], rdn_der, AlgorithmId_der, 
                        datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc), datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc), 
                        subjectPKinfo_der)
with open('tmp.der', 'wb') as f:
    f.write(raw_bytes)

# # decoder.enter()  # Входим в Name (SEQUENCE OF RelativeDistinguishedName)
# # while not decoder.eof():
# #     decoder.enter()  # Входим в RelativeDistinguishedName (SET OF AttributeTypeAndValue)
# #     while not decoder.eof():
# #         decoder.enter()  # Входим в AttributeTypeAndValue (SEQUENCE)
# #         oid = decoder.read()
# #         value = decoder.read()
# #         print(f"  OID: {oid}, Value: {value}")
# #         decoder.leave()
# #     decoder.leave()
# # decoder.leave()

# # SubjectPublicKeyInfo
# print("\nSubject Public Key Info:")
# decoder.enter()  # Входим в SubjectPublicKeyInfo
# # AlgorithmIdentifier
# decoder.enter()
# algorithm_oid = decoder.read()
# print(f"  Algorithm OID: {algorithm_oid}")
# decoder.leave()
# # SubjectPublicKey (BIT STRING)
# public_key = decoder.read()
# print(f"  Public Key (bits): {len(public_key)*8} bits")
# decoder.leave()

# # Attributes (если есть)
# if not decoder.eof():
#     print("\nAttributes:")
#     decoder.enter()
#     while not decoder.eof():
#         decoder.enter()
#         oid = decoder.read()
#         print(f"  Attribute OID: {oid}")
#         decoder.enter()
#         value = decoder.read()
#         print(f"    Value: {value}")
#         decoder.leave()
#         decoder.leave()
#     decoder.leave()

# decoder.leave()  # Выходим из certificationRequestInfo

# # 2. Декодируем signatureAlgorithm
# print("\nSignature Algorithm:")
# decoder.enter()
# algorithm_oid = decoder.read()
# print(f"  Algorithm OID: {algorithm_oid}")
# decoder.leave()

# # 3. Декодируем signature (BIT STRING)
# signature = decoder.read()
# print(f"\nSignature (bits): {len(signature)*8} bits")

# decoder.leave()  # Выходим из основной SEQUENCE