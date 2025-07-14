

class ErrParamsTemplate(Exception):
    def __init__(self, message, *args):
        message += " ErrParamsTemplate "
        super().__init__(message, *args)

class RDNTemplate:
    def __init__(self):
        self.surname = True
        self.givenName = True
        self.organizationalUnitName = True
        self.title = True
        self.commonName = True
        self.organizationName = True
        self.countryName = True
        self.stateOrProvinceName = True
        self.localityName = True
        self.streetAddress = True

class CertTemplate:
    def __init__(self, rdnTemplate: RDNTemplate):
        self.rdnTemplate = rdnTemplate