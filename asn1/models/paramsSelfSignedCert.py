from pyasn1_modules import rfc5280
from datetime import datetime
from models.CertTemplate import RDNTemplate, ErrParamsTemplate
from models.AlgParams import AlgTypes

class ParamsRDN:
    oid_surname = str(rfc5280.id_at_surname)
    oid_givenName = str(rfc5280.id_at_givenName)
    oid_organizationalUnitName = str(rfc5280.id_at_organizationalUnitName)
    oid_title = str(rfc5280.id_at_title)
    oid_commonName = str(rfc5280.id_at_commonName)
    oid_organizationName = str(rfc5280.id_at_organizationName)
    oid_countryName = str(rfc5280.id_at_countryName)
    oid_stateOrProvinceName = str(rfc5280.id_at_stateOrProvinceName)
    oid_localityName = str(rfc5280.id_at_localityName)
    oid_streetAddress = '2.5.4.9'  # OID для streetAddress

    def __init__(self, surname: str='', givenName: str='', organizationalUnitName: str='', 
                 title: str='', commonName: str='', organizationName: str='',
                 countryName: str='', stateOrProvinceName: str='', 
                 streetAddress: str='', localityName: str=''):
        self.params = {
            self.oid_surname: surname,
            self.oid_givenName: givenName,
            self.oid_organizationalUnitName: organizationalUnitName,
            self.oid_title: title,
            self.oid_commonName: commonName,
            self.oid_organizationName: organizationName,
            self.oid_countryName: countryName,
            self.oid_stateOrProvinceName: stateOrProvinceName,
            self.oid_localityName: localityName,
            self.oid_streetAddress: streetAddress
        }

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
        if t.surname and not self.params[self.oid_surname]:
            raise ErrParamsTemplate("Missing required field: surname")
        elif not t.surname:
            self.params[self.oid_surname] = ''

        if t.givenName and not self.params[self.oid_givenName]:
            raise ErrParamsTemplate("Missing required field: givenName")
        elif not t.givenName:
            self.params[self.oid_givenName] = ''

        if t.organizationalUnitName and not self.params[self.oid_organizationalUnitName]:
            raise ErrParamsTemplate("Missing required field: organizationalUnitName")
        elif not t.organizationalUnitName:
            self.params[self.oid_organizationalUnitName] = ''

        if t.title and not self.params[self.oid_title]:
            raise ErrParamsTemplate("Missing required field: title")
        elif not t.title:
            self.params[self.oid_title] = ''

        if t.commonName and not self.params[self.oid_commonName]:
            raise ErrParamsTemplate("Missing required field: commonName")
        elif not t.commonName:
            self.params[self.oid_commonName] = ''

        if t.organizationName and not self.params[self.oid_organizationName]:
            raise ErrParamsTemplate("Missing required field: organizationName")
        elif not t.organizationName:
            self.params[self.oid_organizationName] = ''

        if t.countryName and not self.params[self.oid_countryName]:
            raise ErrParamsTemplate("Missing required field: countryName")
        elif not t.countryName:
            self.params[self.oid_countryName] = ''

        if t.stateOrProvinceName and not self.params[self.oid_stateOrProvinceName]:
            raise ErrParamsTemplate("Missing required field: stateOrProvinceName")
        elif not t.stateOrProvinceName:
            self.params[self.oid_stateOrProvinceName] = ''

        if t.localityName and not self.params[self.oid_localityName]:
            raise ErrParamsTemplate("Missing required field: localityName")
        elif not t.localityName:
            self.params[self.oid_localityName] = ''

        if t.streetAddress and not self.params[self.oid_streetAddress]:
            raise ErrParamsTemplate("Missing required field: streetAddress")
        elif not t.streetAddress:
            self.params[self.oid_streetAddress] = ''

    def __str__(self):
        """Строковое представление всех заполненных полей"""
        fields = [
            (self.oid_surname, "Surname"),
            (self.oid_givenName, "Given Name"),
            (self.oid_organizationalUnitName, "Organizational Unit"),
            (self.oid_title, "Title"),
            (self.oid_commonName, "Common Name"),
            (self.oid_organizationName, "Organization"),
            (self.oid_countryName, "Country"),
            (self.oid_stateOrProvinceName, "State/Province"),
            (self.oid_localityName, "Locality"),
            (self.oid_streetAddress, "Street Address")
        ]
        
        result = []
        for oid, name in fields:
            if self.params[oid]:
                result.append(f"{name}: {self.params[oid]}")
        
        return "\n".join(result)

    def get_list(self):
        """Возвращает список заполненных полей в виде кортежей (значение, OID)"""
        fields_order = [
            self.oid_countryName,
            self.oid_organizationName,
            self.oid_organizationalUnitName,
            self.oid_stateOrProvinceName,
            self.oid_commonName,
            self.oid_localityName,
            self.oid_title,
            self.oid_surname,
            self.oid_givenName,
            self.oid_streetAddress
        ]
        
        return [(self.params[oid], oid) for oid in fields_order if self.params[oid]]


class ParamsSelfSignedCert:
    def __init__(self, beg_validity_date: datetime, end_validity_date: datetime, 
                 alg_type: AlgTypes,
                 paramsRDN: ParamsRDN):
        self.beg_validity_date = beg_validity_date  # время начала действия сертификата
        self.end_validity_date = end_validity_date  # время ококнчания действия сертификата
        self.alg_type = alg_type                    # тип алгоритмов шифрования ("b", "a") # TODO пока только "b"
        self.paramsRDN = paramsRDN

    def __str__(self):
        res = f"validity: {self.beg_validity_date.strftime('%y%m%d%H%M%SZ')}---{self.end_validity_date.strftime('%y%m%d%H%M%SZ')}\n"
        res += f"alg_type: {self.alg_type}\n"
        res += str(self.paramsRDN)
        return res

    def validate() -> bool:
        return True