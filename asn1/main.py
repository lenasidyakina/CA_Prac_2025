from datetime import datetime, timezone

from asn1_parse import CertsAsn1, bytes_to_pem, create_cert, generate_serial_num
from models.paramsSelfSignedCert import ParamsSelfSignedCert
from models.RevokedCertificates import RevokedCertificates

    
'''Пример создания списка отозванных сертификатов'''
def crl_test():
    # получаем из БД:
    rlist = []
    for _ in range(3):
        serial_num = generate_serial_num() 
        r = RevokedCertificates(serialNumber=serial_num, revocationDate=datetime(2025, 7, 10, tzinfo=timezone.utc))
        rlist.append(r)

    # TODO Данные из корневого сертификата (их получение будет добавлено потом)
    p = ParamsSelfSignedCert("", "", "", "", "", "", "TcountryName", "", "", "") 

    crl_bytes = create_crl(
        revokedCerts=rlist, 
        issuer=p, 
        thisUpdate=datetime.now(tz=timezone.utc),
        nextUpdate=datetime(2027, 7, 10, tzinfo=timezone.utc))

    
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL")) # !!! pem_type - НЕ МЕНЯТЬ

'''Пример создания сертификата'''
def create_cert_test():
    with open('./csr/full.p10', 'r') as pem_file:
        pem_csr = pem_file.read()

    serial_num = generate_serial_num() 
    # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
    cert_bytes = create_cert(serial_num, pem_csr)
    
    with open('res.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ

'''Пример создания самоподписанного сертификата'''
# TODO
def create_selfsigned_cert_test():
    certsAsn1 = CertsAsn1()

    p = ParamsSelfSignedCert("Tsurname", "TgivenName", "TorganizationalUnitName", "Ttitle",
                 "TcommonName", "TorganizationName",
                 "TcountryName", "TstateOrProvinceName", "TstreetAddress", "TlocalityName")
    # print(p)

    serial_num = generate_serial_num() 
    # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
    cert_bytes = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
    with open('cert.der', 'wb') as f:
        f.write(cert_bytes)
    with open('cert.pem', 'w') as f:
        f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))

if __name__ == '__main__':
    create_selfsigned_cert_test()
    # create_cert_test()

    # try:
    #     wrapper = BicryWrapper()
        
    #     # Экспортируем ключ для пользователя
    #     public_key = wrapper.export_public_key("Ivanov")

    #     # Выводим результаты
    #     print(f"Successfully exported public key ({len(public_key)} bytes):")
    #     print(public_key.hex())

    #     #Подписываем буфер ЭП
    #     wrapper.electronic_signature()
        
    # except Exception as e:
    #     print(f"Error: {e}")

    

    
    