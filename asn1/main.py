import base64
import asn1
from asn1_parse import *

if __name__ == '__main__':
    pem_file_path = './csr/full.p10'
    with open(pem_file_path, 'r') as pem_file:
        pem_csr = pem_file.read()

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
    with open('res.der', 'wb') as f:
        f.write(raw_bytes)
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(raw_bytes, "CERTIFICATE"))