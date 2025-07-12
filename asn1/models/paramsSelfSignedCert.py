from pyasn1_modules import rfc5280
from datetime import datetime, timezone

class ParamsSelfSignedCert:
    def __init__(self, beg_validity_date: datetime, end_validity_date: datetime, 
                 alg_type: chr,
                 surname: str,  givenName: str,  organizationalUnitName: str, title: str, 
                 commonName:str, organizationName: str, 
                 countryName: str, stateOrProvinceName: str, streetAddress: str, localityName :str):
        self.beg_validity_date = beg_validity_date  # время начала действия сертификата
        self.end_validity_date = end_validity_date  # время ококнчания действия сертификата
        self.alg_type = alg_type                    # тип алгоритмов шифрования ("b", "a") # TODO пока только "b"
        self.surname = (surname, str(rfc5280.id_at_commonName))                     # фамилия
        self.givenName = (givenName, str(rfc5280.id_at_givenName))                  # имя
        self.organizationalUnitName = (organizationalUnitName, 
                                       str(rfc5280.id_at_organizationalUnitName))   # подразделение
        self.title = (title, str(rfc5280.id_at_title))                              # должность

        self.commonName = (commonName, str(rfc5280.id_at_commonName))                               # общее имя
        self.organizationName = (organizationName, str(rfc5280.id_at_organizationName))             # наименование организации
        
        self.countryName = (countryName, str(rfc5280.id_at_countryName))                            # страна
        self.stateOrProvinceName = (stateOrProvinceName, str(rfc5280.id_at_stateOrProvinceName))    # регион
        self.localityName = (localityName, str(rfc5280.id_at_localityName))                         # нас пункт
        self.streetAddress = (streetAddress, '2.5.4.9')                           # адрес

    def __str__(self):
        restxt = ''
        restxt += f"{self.surname}\n{self.givenName}\n{self.organizationalUnitName}\n" + \
            f"{self.title}\n{self.commonName}\n{self.organizationName}\n{self.countryName}\n" + \
                f"{self.stateOrProvinceName}\n{self.localityName}\n{self.streetAddress}"
        return restxt
    
    def get_list(self):
        lst = [self.surname, self.givenName, self.organizationalUnitName, self.title, 
                self.commonName, self.organizationName, 
                self.countryName, self.stateOrProvinceName, self.localityName, self.streetAddress]
        return [el for el in lst if el[0] != '']

    def validate() -> bool:
        return True