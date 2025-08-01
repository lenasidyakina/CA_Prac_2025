import asn1
from datetime import datetime
from typing import List, Tuple
from pyasn1_modules import rfc5280

from .asn1_parse import pem_to_bytes, tbsCertificate_encode, rdn_encode, \
    block_to_raw_bytes, block_length, UTC_DATETIME_FORMAT, rdn_decode, GENERALIZED_TIME_FORMAT
from .models.paramsSelfSignedCert import ParamsSelfSignedCert
from .models.CertTemplate import CertTemplate
from .models.RevokedCertificates import RevokedCertificates
from .models.RootCert import RootCert, restore_root_cert
from .models.AlgParams import ALL_ALG_PARAMS, AlgTypes, AlgParams
from bicry.bicry import BicryWrapper

class ErrNoRootCert(Exception):
    def __init__(self, message, *args):
        message += " ErrNoRootCert "
        super().__init__(message, *args)

class CertsAsn1:
    def __init__(self, rootCert: RootCert =None):
        self.rootCert = None
        self.bicrypt = BicryWrapper(lib_path='libbicry_openkey.so')
        # if self.rootCert is None:
        #     self.bicrypt = BicryWrapper(lib_path='libbicry_openkey.so', param=None)
        # else:
        #     self.bicrypt = BicryWrapper(lib_path='libbicry_openkey.so', param=self.rootCert.alg_type.value)
        #     self.bicrypt.compare_keys(self.rootCert.public_key)
        #     pwd, privkey = self.bicrypt.get_private_key_with_password()
        #     self.rootCert.password = pwd
        #     self.rootCert.private_key = privkey

    '''Создает самопоодписанный сертификат  на основе ParamsSelfSignedCert.get_list.get_list()
    return самоподписанный сертификат, открытый ключ, пароль'''
    def create_selfsigned_cert(self, params: ParamsSelfSignedCert, serial_num: int) -> Tuple[bytes, bytes, str]:
        version = 2
        rdn_bytes = rdn_encode(params.paramsRDN)
        alg_param = ALL_ALG_PARAMS[params.alg_type]

        password, private_key, public_key = self.bicrypt.generate_temp_keypair("Ivanov", param=params.alg_type.value)
        # public_key = self.bicrypt.generate_keypair("Ivanov", param=params.alg_type.value)   

        tbsCertificate_bytes = tbsCertificate_encode(
            serial_num=serial_num, version=version, 
            issuer_rdn_bytes=rdn_bytes, 
            subject_rdn_bytes=rdn_bytes,
            sign_algid_bytes=self._signAlgId_encode(alg_param=alg_param),
            beg_date=params.beg_validity_date, end_date=params.end_validity_date,
            subjectPKinfo_bytes=self._subjPKInfo_encode(alg_param=alg_param, public_key=public_key),
            attr_bytes_list=params.extentions.extentions_cert_encode(public_key)
        )

        signature_bytes = self.bicrypt.temp_electronic_signature(tbsCertificate_bytes)
        # signature_bytes = self.bicrypt.electronic_signature(tbsCertificate_bytes)
        cert_bytes = self._signature_encode(
            alg_param=alg_param,
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        # self.rootCert = RootCert(serial_num=serial_num,
        #                          issuer_rdn_bytes=rdn_bytes,
        #                          alg_type=params.alg_type,
        #                          beg_validity_date=params.beg_validity_date, 
        #                          end_validity_date=params.end_validity_date,
        #                          public_key=public_key, cert_bytes=cert_bytes)
        # self.rootCert.password = password
        # self.rootCert.private_key = private_key
        return cert_bytes, private_key, password

    # def change_active_root_cert(self, cert_bytes: bytes, private_key: bytes, password: str):
    #     self.rootCert = restore_root_cert(cert_bytes)
    #     self.bicrypt.change_active_cert(param=self.rootCert.alg_type.value,
    #                                         password=password,
    #                                         private_key=private_key,
    #                                         public_key=self.rootCert.public_key)

    def change_active_root_cert(self, cert_bytes: bytes, private_key: bytes, password: str):
        try:
            rootCert = restore_root_cert(cert_bytes)
            self.bicrypt.change_active_cert(param=rootCert.alg_type.value,
                                                password=password,
                                                private_key=private_key,
                                                public_key=rootCert.public_key)
        except Exception as e:
            raise
        self.rootCert = rootCert

    ''' Создает сертификат на основе запроса на сертификат'''
    def create_cert(self, serial_num: int, 
                    beg_validity_date: datetime, end_validity_date: datetime, 
                    cert_template: CertTemplate,
                    pem_csr: str) -> bytes:
        if self.rootCert is None:
            raise ErrNoRootCert("no root cert created")
        der_csr = pem_to_bytes(pem_csr)

        decoder = asn1.Decoder()
        decoder.start(der_csr)
        decoder.enter()     # CertificationRequest
        decoder.enter()     # certificationRequestInfo

        decoder.read()  # version
        version = 2     # when extensions are used, as expected in this profile (rfc5280), version MUST be 3 (value is 2)

        subject_rdn_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()
        subject_rdn = rdn_decode(subject_rdn_der)
        subject_rdn.fit_template(cert_template.rdnTemplate)
        subject_rdn_der = rdn_encode(subject_rdn)

        # SubjectPublicKeyInfo
        subjectPKinfo_der = block_to_raw_bytes(der_csr[decoder._get_current_position():])
        decoder.read()

        # AttributeValue  SEQUENCE
        attr_bytes_list = [] # список блококов байт из которых состоял AttributeValue  SEQUENCE
        decoder.enter() # Attributes [?]
        decoder.enter() # Attributes SEQUENCE
        _, v = decoder.read()   # AttributeType
        assert v == '1.2.840.113549.1.9.14' # стандарт поддерживаемых атрибутов
        decoder.enter() # values SET
        len_attrValue = block_length(der_csr[decoder._get_current_position():])
        decoder.enter() # AttributeValue  SEQUENCE
        start_pos = decoder._get_current_position()
        while decoder._get_current_position() - start_pos < len_attrValue:
            attr_bytes = block_to_raw_bytes(der_csr[decoder._get_current_position():])
            attr_bytes_list.append(attr_bytes)
            t, v = decoder.read()

        # TODO Получить данные о ЦС и вставить из в extentoins: добавить в attr_bytes_list
        decoder.leave() # out AttributeValue  SEQUENCE
        decoder.leave() # out values SET
        decoder.leave() # out Attributes SEQUENCE
        decoder.leave() # out Attributes [?]

        decoder.leave() # out certificationRequestInfo

        alg_type = ALL_ALG_PARAMS[self.rootCert.alg_type]
        tbsCertificate_bytes = tbsCertificate_encode(
            serial_num=serial_num, version=version, 
            issuer_rdn_bytes=self.rootCert.issuer_rdn_bytes, 
            subject_rdn_bytes=subject_rdn_der,
            sign_algid_bytes=self._signAlgId_encode(alg_param=alg_type),
            beg_date=beg_validity_date, end_date=end_validity_date,
            subjectPKinfo_bytes=subjectPKinfo_der,
            attr_bytes_list=attr_bytes_list
        )

        signature_bytes = self.bicrypt.electronic_signature(tbsCertificate_bytes)
        cert_bytes = self._signature_encode(
            alg_param=alg_type,
            tbs_bytes=tbsCertificate_bytes, 
            signature_bytes=signature_bytes)
        
        return cert_bytes

    def create_crl(self, revokedCerts: List[RevokedCertificates], 
                thisUpdate: datetime, nextUpdate: datetime) -> bytes:
        if self.rootCert is None:
            raise ErrNoRootCert("no root cert created")
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # TBSCertList 

        version = 1
        encoder.write(version, asn1.Numbers.Integer) 

        # encoder.enter(asn1.Numbers.Sequence)    # AlgorithmIdentifier
        alg_type = ALL_ALG_PARAMS[self.rootCert.alg_type]
        encoder._emit(self._signAlgId_encode(alg_type))
        # encoder.leave()                         # out AlgorithmIdentifier   

        issuer_rdn_bytes = self.rootCert.issuer_rdn_bytes
        encoder._emit(issuer_rdn_bytes)

        encoder.write(thisUpdate.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)
        encoder.write(nextUpdate.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)

        # revokedCertificates
        if len(revokedCerts) > 0:
            encoder.enter(asn1.Numbers.Sequence)    # revokedCertificates
            for rcert in revokedCerts:
                encoder.enter(asn1.Numbers.Sequence)
                encoder.write(rcert.serialNumber, asn1.Numbers.Integer)
                encoder.write(rcert.revocationDate.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)
                encoder.enter(asn1.Numbers.Sequence)    # crlEntryExtensions

                encoder.enter(asn1.Numbers.Sequence)    # reasonCode
                encoder.write(str(rfc5280.id_ce_cRLReasons), asn1.Numbers.ObjectIdentifier)
                value_encoder = asn1.Encoder()
                value_encoder.start()
                value_encoder.write(rcert.crlReasonCode.value, asn1.Numbers.Enumerated)
                encoded_value = value_encoder.output()
                encoder.write(encoded_value, asn1.Numbers.OctetString)
                encoder.leave()                         # out reasonCode

                # encoder.enter(asn1.Numbers.Sequence)    # invalidityDate
                # encoder.write(str(rfc5280.id_ce_invalidityDate), asn1.Numbers.ObjectIdentifier)
                # # encoder.write(rcert.invalidityDate.strftime(GENERALIZED_TIME_FORMAT), asn1.Numbers.GeneralizedTime)
                # encoder.write(rcert.invalidityDate.strftime(UTC_DATETIME_FORMAT), asn1.Numbers.UTCTime)
                # encoder.leave()                         # out invalidityDate

                encoder.leave()                         # out crlEntryExtensions
                encoder.leave() 
            encoder.leave()                         # out revokedCertificates  
        # TODO crlExtensions  
        # encoder.enter(nr=0, cls=asn1.Classes.Context) 
        # encode.write(version, asn1.Numbers.Integer)  
        # encoder.leave()         
        
        encoder.leave()                         # out TBSCertList   
        
        tbsCertList_bytes = encoder.output()
        signature_bytes = self.bicrypt.electronic_signature(tbsCertList_bytes)
        crl_bytes = self._signature_encode(
            alg_param=alg_type,
            tbs_bytes=tbsCertList_bytes, 
            signature_bytes=signature_bytes)

        return crl_bytes
    
    
    def _signature_encode(self, alg_param: AlgParams, tbs_bytes: bytes, signature_bytes: bytes):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Certificate SEQUENCE
        encoder._emit(tbs_bytes)
        encoder._emit(self._signAlgId_encode(alg_param=alg_param))
        encoder.write(signature_bytes, asn1.Numbers.BitString)
        encoder.leave()                         # out Certificate
        cert_bytes = encoder.output()
        return cert_bytes

    def _signAlgId_encode(self, alg_param: AlgParams):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(alg_param.signAlgId, asn1.Numbers.ObjectIdentifier)  
        encoder.leave()
        alg_bytes = encoder.output()
        return alg_bytes
    
    def _subjPKInfo_encode(self, alg_param: AlgParams, public_key: bytes):
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # SubjectPublicKeyInfo
        encoder.enter(asn1.Numbers.Sequence)    # AlgorithmIdentifier
        encoder.write(alg_param.subjPKAlgId, asn1.Numbers.ObjectIdentifier)  
        encoder.enter(asn1.Numbers.Sequence)    # params
        encoder.write(alg_param.subjPKAlgIdParam1, asn1.Numbers.ObjectIdentifier)  
        encoder.write(alg_param.subjPKAlgIdParam2, asn1.Numbers.ObjectIdentifier) 
        encoder.leave()                         # out params
        encoder.leave()                         # out AlgorithmIdentifier
        encoderPK = asn1.Encoder()
        encoderPK.start()
        encoderPK.write(public_key, asn1.Numbers.OctetString)  
        subjectPK_der = encoderPK.output() 
        encoder.write(subjectPK_der, asn1.Numbers.BitString)
        encoder.leave()                         # out SubjectPublicKeyInfo
        alg_bytes = encoder.output()
        return alg_bytes
    
