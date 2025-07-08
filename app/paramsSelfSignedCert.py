class ParamsSelfSignedCert:
    def __init__(self, surname: str,  givenName: str,  organizationalUnitName: str, title: str, 
                 commonName:str, organizationName: str, 
                 countryName: str, stateOrProvinceName: str, streetAddress: str, localityName :str):
        self.surname = surname                                  # фамилия
        self.givenName = givenName                              # имя
        self.organizationalUnitName = organizationalUnitName    # подразделение
        self.title = title                                      # должность

        self.commonName = commonName                            # общее имя
        self.organizationName = organizationName                # наименование организации
        
        self.countryName = countryName                          # страна
        self.stateOrProvinceName = stateOrProvinceName          # регион
        self.localityName = localityName                        # нас пункт
        self.streetAddress = streetAddress                      # адрес

    def validate() -> bool:
        return true
