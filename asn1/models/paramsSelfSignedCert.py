from pyasn1_modules import rfc5280
from datetime import datetime
from models.CertTemplate import RDNTemplate


class ParamsRDN:
    def __init__(self, surname: str='',  givenName: str='',  organizationalUnitName: str='', title: str='', 
                 commonName:str='', organizationName: str='', 
                 countryName: str='', stateOrProvinceName: str='', streetAddress: str='', localityName :str=''):
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
        self.streetAddress = (streetAddress, '2.5.4.9')                                             # адрес

    def fit_template(self, t: RDNTemplate):
        """
        Проверяет соответствие параметров RDN шаблону.
        Если поле обязательно в шаблоне (True), но не заполнено (пустая строка) - вызывает ErrParamsTemplate.
        Если поле не требуется в шаблоне (False) - очищает его значение.
        
        Args:
            t: RDNTemplate - шаблон для проверки
            
        Raises:
            ErrParamsTemplate: если обязательное поле не заполнено
        """
        # Проверка обязательных полей
        if t.surname and not self.surname[0]:
            raise ErrParamsTemplate("Missing required field: surname")
        elif not t.surname:
            self.surname = ('', self.surname[1])  # Сохраняем OID, очищаем значение

        if t.givenName and not self.givenName[0]:
            raise ErrParamsTemplate("Missing required field: givenName")
        elif not t.givenName:
            self.givenName = ('', self.givenName[1])

        if t.organizationalUnitName and not self.organizationalUnitName[0]:
            raise ErrParamsTemplate("Missing required field: organizationalUnitName")
        elif not t.organizationalUnitName:
            self.organizationalUnitName = ('', self.organizationalUnitName[1])

        if t.title and not self.title[0]:
            raise ErrParamsTemplate("Missing required field: title")
        elif not t.title:
            self.title = ('', self.title[1])

        if t.commonName and not self.commonName[0]:
            raise ErrParamsTemplate("Missing required field: commonName")
        elif not t.commonName:
            self.commonName = ('', self.commonName[1])

        if t.organizationName and not self.organizationName[0]:
            raise ErrParamsTemplate("Missing required field: organizationName")
        elif not t.organizationName:
            self.organizationName = ('', self.organizationName[1])

        if t.countryName and not self.countryName[0]:
            raise ErrParamsTemplate("Missing required field: countryName")
        elif not t.countryName:
            self.countryName = ('', self.countryName[1])

        if t.stateOrProvinceName and not self.stateOrProvinceName[0]:
            raise ErrParamsTemplate("Missing required field: stateOrProvinceName")
        elif not t.stateOrProvinceName:
            self.stateOrProvinceName = ('', self.stateOrProvinceName[1])

        if t.localityName and not self.localityName[0]:
            raise ErrParamsTemplate("Missing required field: localityName")
        elif not t.localityName:
            self.localityName = ('', self.localityName[1])

        if t.streetAddress and not self.streetAddress[0]:
            raise ErrParamsTemplate("Missing required field: streetAddress")
        elif not t.streetAddress:
            self.streetAddress = ('', self.streetAddress[1])

    def __str__(self):
        restxt = ''
        restxt += f"{self.surname}\n{self.givenName}\n{self.organizationalUnitName}\n" + \
            f"{self.title}\n{self.commonName}\n{self.organizationName}\n{self.countryName}\n" + \
                f"{self.stateOrProvinceName}\n{self.localityName}\n{self.streetAddress}"
        return restxt
    
    def get_list(self):
        lst = [self.countryName, self.organizationName, self.organizationalUnitName, 
               self.stateOrProvinceName, self.commonName, self.localityName, self.title, 
                self.surname, self.givenName, self.streetAddress]
        return [el for el in lst if el[0] != '']



class ParamsSelfSignedCert:
    def __init__(self, beg_validity_date: datetime, end_validity_date: datetime, 
                 alg_type: chr,
                 paramsRDN: ParamsRDN):
        self.beg_validity_date = beg_validity_date  # время начала действия сертификата
        self.end_validity_date = end_validity_date  # время ококнчания действия сертификата
        self.alg_type = alg_type                    # тип алгоритмов шифрования ("b", "a") # TODO пока только "b"
        self.paramsRDN = paramsRDN

    def __str__(self):
        res = f"validity: {self.beg_validity_date.strftime("%y%m%d%H%M%SZ")}---{self.end_validity_date.strftime("%y%m%d%H%M%SZ")}\n"
        res += f"alg_type: {self.alg_type}\n"
        res += str(self.paramsRDN)
        return res

    def validate() -> bool:
        return True