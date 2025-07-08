from asn1_parse import bytes_to_pem, create_cert

import asn1
from paramsSelfSignedCert import ParamsSelfSignedCert
from pyasn1_modules import rfc5280
    

def create_rdn(params: ParamsSelfSignedCert) -> bytes:
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

if __name__ == '__main__':
    p = ParamsSelfSignedCert("Tsurname", "TgivenName", "TorganizationalUnitName", "Ttitle",
                 "TcommonName", "TorganizationName",
                 "TcountryName", "TstateOrProvinceName", "TstreetAddress", "TlocalityName")
    # print(p)
    cert_bytes = create_rdn(p)
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))

#     with open('./csr/full.p10', 'r') as pem_file:
#         pem_csr = pem_file.read()
#     cert_bytes = create_cert(pem_csr)
#     with open('res.der', 'wb') as f:
#         f.write(cert_bytes)
#     with open('res.pem', 'w') as f:
#         f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))
    