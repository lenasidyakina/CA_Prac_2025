from datetime import datetime, timezone

from cert_parse import CertsAsn1
from asn1_parse import bytes_to_pem, generate_serial_num
from models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN, ExtentionsCert
from models.CertTemplate import CertTemplate, RDNTemplate
from models.RevokedCertificates import RevokedCertificates, CRLReasonCode
from models.AlgParams import AlgTypes

ROOT_CERT_PATH = './tmp/root_cert.der'
    
'''Пример создания списка отозванных сертификатов'''
def crl_test(certsAsn1: CertsAsn1):
    # получаем из БД:
    reasons = [CRLReasonCode.cACompromise, CRLReasonCode.unspecified, CRLReasonCode.affiliationChanged]
    rlist = []
    for i in range(3):
        serial_num = generate_serial_num() 
        r = RevokedCertificates(serialNumber=serial_num, 
                                revocationDate=datetime(2025, 7, 10, tzinfo=timezone.utc),
                                crlReasonCode=reasons[i],
                                invalidityDate=datetime(1900 + i, 7, 10, tzinfo=timezone.utc))
        rlist.append(r)

    crl_bytes = certsAsn1.create_crl(
        revokedCerts=rlist, 
        thisUpdate=datetime.now(tz=timezone.utc),
        nextUpdate=datetime(2027, 7, 10, tzinfo=timezone.utc))

    
    with open('crl.pem', 'w') as f:
        f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL")) # !!! pem_type - НЕ МЕНЯТЬ

'''Пример создания сертификата'''
def create_cert_test(certsAsn1: CertsAsn1):
    with open('./csr/full.p10', 'r') as pem_file:
        pem_csr = pem_file.read()

    serial_num = generate_serial_num() 
    # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
    rdn_template = RDNTemplate()
    rdn_template.surname = rdn_template.givenName = rdn_template.streetAddress = False
    cert_template = CertTemplate(rdn_template)
    cert_bytes = certsAsn1.create_cert(serial_num=serial_num, 
                                       beg_validity_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                                       end_validity_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                                       cert_template=cert_template, 
                                       pem_csr=pem_csr)
    with open("res.cer", 'wb') as f:
        f.write(cert_bytes)
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ

'''Пример создания самоподписанного сертификата'''
# TODO
def create_selfsigned_cert_test() -> CertsAsn1:
    certsAsn1 = CertsAsn1()

    prdn = ParamsRDN(surname="Tsurname", givenName="TgivenName", 
                        organizationalUnitName="TorganizationalUnitName", title="Ttitle",
                        commonName="TcommonName", organizationName="TorganizationName",
                        countryName="TcountryName", stateOrProvinceName="TstateOrProvinceName", 
                        streetAddress="TstreetAddress", localityName="TlocalityName")
    extentions = ExtentionsCert()
    extentions.basicConstraints = True
    extentions.basicConstraints_subject_is_CA = True
    extentions.basicConstraints_max_depth_certs = 3

    extentions.keyUsage = True
    extentions.keyUsage_critical = True
    extentions.keyUsage_cRLSign = True

    extentions.subjectKeyIdentifier = True
    p = ParamsSelfSignedCert(alg_type=AlgTypes.a, 
                             beg_validity_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                             end_validity_date=datetime(2026, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                             paramsRDN=prdn, extentions=extentions)

    serial_num = generate_serial_num() 
    # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
    cert_bytes, private_key, password = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
    # Пережать пользователю cert_bytes, private_key, password

    print(f"saved to {ROOT_CERT_PATH}, './tmp/root_cert.pem'")
    with open(ROOT_CERT_PATH, 'wb') as f:
        f.write(cert_bytes)
    with open('./tmp/root_cert.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))


    # Сделать самоподписанный серт корневым
    certsAsn1.change_active_root_cert(cert_bytes=cert_bytes,
                                      private_key=private_key,
                                      password=password)
    print(certsAsn1.rootCert)
    return certsAsn1
    
    


if __name__ == '__main__':

    certsAsn1 = create_selfsigned_cert_test() 
    create_cert_test(certsAsn1)
    crl_test(certsAsn1)

    

    
    