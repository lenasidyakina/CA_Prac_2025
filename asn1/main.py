import base64
import asn1
from asn1_parse import bytes_to_pem, create_cert


    

if __name__ == '__main__':
    with open('./csr/full.p10', 'r') as pem_file:
        pem_csr = pem_file.read()
    cert_bytes = create_cert(pem_csr)
    with open('res.der', 'wb') as f:
        f.write(cert_bytes)
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))
    