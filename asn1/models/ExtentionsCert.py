from typing import List
import asn1
from pyasn1_modules import rfc5280
import hashlib

''' Как заполнять
Есnm вид расширения, 
и если расширение этого типа пользователь хочет добавить то ставит self.тип_расширения - True 
и опредеояет value этого расширения (оно помечается как self.тип_расширения_что-то) '''
class ExtentionsCert:
    def __init__(self):
        self.basicConstraints = False                   # будет ли добавлено это расширение
        self.basicConstraints_critical = False          # является ли расширение критичным
        self.basicConstraints_subject_is_CA = True      # является ли subject (для самоподписанного всегда True!!!) сертификата центром сертификации
        self.basicConstraints_max_depth_certs = None    # макс число сертификатов которые могут быть в цепочке дальше

        # Key Usage
        self.keyUsage = False
        self.keyUsage_critical = False
        self.keyUsage_digitalSignature = False          # Ключ используется для проверки цифровых подписей (кроме подписей на сертификатах и CRL).
        self.keyUsage_nonRepudiation = False            # Ключ используется для проверки подписей, обеспечивающих неотказуемость (защита от отказа от подписи).
        self.keyUsage_keyEncipherment = False           # Ключ применяется для шифрования других ключей (например, RSA-ключ для защиты симметричного ключа).
        self.keyUsage_dataEncipherment = False          # Ключ напрямую шифрует пользовательские данные (редко используется, обычно вместо этого применяют keyEncipherment).
        self.keyUsage_keyAgreement = False              # Ключ используется для согласования ключей (например, алгоритм Диффи-Хеллмана).
        self.keyUsage_keyCertSign = False               # Ключ применяется для подписи сертификатов (только для CA!). Должен использоваться вместе с cA=true в BasicConstraints.
        self.keyUsage_cRLSign = False                   # Ключ проверяет подписи списков отзыва (CRL).
        self.keyUsage_encipherOnly = False              # (Только при keyAgreement) Ключ может только шифровать данные при согласовании ключей.
        self.keyUsage_decipherOnly = False              # (Только при keyAgreement) Ключ может только расшифровывать данные при согласовании ключей.
        
        self.subjectKeyIdentifier = False               # идентификатор ключа субьекта (ЦС)

    def extentions_cert_encode(self, public_key: bytes) -> List[bytes]:
        extentions_bytes_list = []
        if self.basicConstraints:
            if self.basicConstraints_max_depth_certs is None:
                raise Exception('error basicConstraints: max_depth_certs is None')
            extentions_bytes_list.append(self._basicConstraints_encode())

        if self.keyUsage:
            extentions_bytes_list.append(self._keyUsage_encode())

        if self.subjectKeyIdentifier:
            extentions_bytes_list.append(self._subjectKeyIdentifier_encode(public_key=public_key))
        return extentions_bytes_list

    
    def _basicConstraints_encode(self) -> bytes:
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Extention
        encoder.write(str(rfc5280.id_ce_basicConstraints), asn1.Numbers.ObjectIdentifier)
        if self.basicConstraints_critical:
            encoder.write(self.basicConstraints_critical, asn1.Numbers.Boolean)

        val_encoder = asn1.Encoder()
        val_encoder.start()
        val_encoder.enter(asn1.Numbers.Sequence)
        val_encoder.write(self.basicConstraints_subject_is_CA, asn1.Numbers.Boolean)
        val_encoder.write(self.basicConstraints_max_depth_certs, asn1.Numbers.Integer)
        val_encoder.leave()
        val_bytes = val_encoder.output()

        encoder.write(val_bytes, asn1.Numbers.OctetString)
        encoder.leave()                         # out Extention

        extention_bytes = encoder.output()
        return extention_bytes

    def _keyUsage_encode(self) -> bytes:
        # Создаем битовую маску
        mask = 0
        if self.keyUsage_digitalSignature: mask |= 1 << 0
        if self.keyUsage_nonRepudiation:   mask |= 1 << 1
        if self.keyUsage_keyEncipherment:  mask |= 1 << 2
        if self.keyUsage_dataEncipherment: mask |= 1 << 3
        if self.keyUsage_keyAgreement:     mask |= 1 << 4
        if self.keyUsage_keyCertSign:      mask |= 1 << 5
        if self.keyUsage_cRLSign:          mask |= 1 << 6
        if self.keyUsage_encipherOnly:     mask |= 1 << 7
        if self.keyUsage_decipherOnly:     mask |= 1 << 8

        # Определяем количество байт (1 или 2)
        num_bytes = 1 if mask <= 0xFF else 2
        key_usage_bytes = mask.to_bytes(num_bytes, byteorder='big', signed=False)


        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Extension
        encoder.write(str(rfc5280.id_ce_keyUsage), asn1.Numbers.ObjectIdentifier)
        if self.keyUsage_critical:
            encoder.write(self.keyUsage_critical, asn1.Numbers.Boolean)

        val_encoder = asn1.Encoder()
        val_encoder.start()
        val_encoder.write(key_usage_bytes, asn1.Numbers.BitString)
        val_bytes = val_encoder.output()

        encoder.write(val_bytes, asn1.Numbers.OctetString)
        encoder.leave()                         # out Extension

        return encoder.output()

    def _subjectKeyIdentifier_encode(self, public_key: bytes) -> bytes:
        hash = hashlib.sha256(public_key).digest()[:20]  # Берем первые 20 байт (160 бит) как в RFC 5280

        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)    # Extention
        encoder.write(str(rfc5280.id_ce_subjectKeyIdentifier), asn1.Numbers.ObjectIdentifier)
        # всегда некритичный

        val_encoder = asn1.Encoder()
        val_encoder.start()
        val_encoder.enter(asn1.Numbers.Sequence)
        val_encoder.write(hash, asn1.Numbers.OctetString)
        val_encoder.leave()
        val_bytes = val_encoder.output()

        encoder.write(val_bytes, asn1.Numbers.OctetString)
        encoder.leave()                         # out Extention

        extention_bytes = encoder.output()
        return extention_bytes

    def __str__(self):
        res = ""
        res += f"basicConstraints: {self.basicConstraints}"
        if not self.basicConstraints:
            res += f"basicConstraints_subject_is_CA={self.basicConstraints_subject_is_CA}\nbasicConstraints_max_depth_certs={self.basicConstraints_max_depth_certs}\n"
        return res