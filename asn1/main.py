from datetime import datetime, timezone

from cert_parse import CertsAsn1
from asn1_parse import bytes_to_pem, generate_serial_num
from models.RootCert import RootCert, restore_root_cert
from models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN
from models.CertTemplate import CertTemplate, RDNTemplate
from models.RevokedCertificates import RevokedCertificates, CRLReasonCode
from models.AlgParams import AlgTypes

ROOT_CERT_PATH = 'root_cert.der'
    
'''Пример создания списка отозванных сертификатов'''
def crl_test():
    # root_cert.der - файл в котором хранится корневой сертификат 
    # Если его нет (корневой серт еще не создали), то надо обработать ошибку
    # Так же может быть ошибка если корневой серт просрочен
    with open(ROOT_CERT_PATH, 'rb') as f:  
        cert_bytes = f.read()
    root = restore_root_cert(cert_bytes)
    print(root)
    certsAsn1 = CertsAsn1(rootCert=root)

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
def create_cert_test():
    # root_cert.der - файл в котором хранится корневой сертификат 
    # Если его нет (корневой серт еще не создали), то надо обработать ошибку
    # Так же может быть ошибка если корневой серт просрочен
    with open(ROOT_CERT_PATH, 'rb') as f:  
        cert_bytes = f.read()
    root = restore_root_cert(cert_bytes)
    print(root)
    certsAsn1 = CertsAsn1(rootCert=root)

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
    
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ

'''Пример создания самоподписанного сертификата'''
# TODO
def create_selfsigned_cert_test():
    certsAsn1 = CertsAsn1()

    prdn = ParamsRDN(surname="Tsurname", givenName="TgivenName", 
                        organizationalUnitName="TorganizationalUnitName", title="Ttitle",
                        commonName="TcommonName", organizationName="TorganizationName",
                        countryName="TcountryName", stateOrProvinceName="TstateOrProvinceName", 
                        streetAddress="TstreetAddress", localityName="TlocalityName")
    p = ParamsSelfSignedCert(alg_type=AlgTypes.A, 
                             beg_validity_date=datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                             end_validity_date=datetime(2026, 6, 7, 0, 0, 0, tzinfo=timezone.utc),
                             paramsRDN=prdn)

    serial_num = generate_serial_num() 
    # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
    cert_bytes, private_key, password = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
    print(certsAsn1.rootCert)
    with open(ROOT_CERT_PATH, 'wb') as f:
        f.write(cert_bytes)
    # with open('root_cert.pem', 'w') as f:
    #     f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))

if __name__ == '__main__':

    create_selfsigned_cert_test() 
    create_cert_test()
    crl_test()

    

    
    