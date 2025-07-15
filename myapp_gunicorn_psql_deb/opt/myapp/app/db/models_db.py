from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, text , CheckConstraint, Date
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import validates
from configparser import ConfigParser
import os
from datetime import datetime
import enum
# from ..asn1_parser.models.RevokedCertificates import CRLReasonCode
#from asn1_parser.models.RevokedCertificates import CRLReasonCode
#from enum_db import CRLReasonText

# обьяснения и перевода перечисленных причин в стандарте нет
class CRLReasonCode(enum.Enum):
    unspecified = 0
    keyCompromise = 1
    cACompromise = 2
    affiliationChanged = 3
    superseded = 4
    cessationOfOperation = 5
    certificateHold = 6
    removeFromCRL = 8

Base = declarative_base()


class Certificate(Base):
    __tablename__ = 'certificates'
    serial_number = Column(
        String(27),  
        primary_key=True,
    )
    
    is_revoked = Column(
        Boolean,
        server_default="false",
        nullable=False
    )
    
    revoke_date = Column(Date)

    revoke_reason = Column(Text)
    #revoke_reason = Column(Integer)

    # send_to_ocsp = Column(
    #     Boolean,
    #     server_default="false",
    #     nullable=False
    # )

    invalidity_date = Column(Date)

    source_serial_number = Column(
        String(27), nullable=False
    )
    
    
    # Валидация на уровне Python
    @validates('serial_number')
    def validate_serial_number(self, key, value):
        if not value.isdigit():
            raise ValueError("Серийный номер сертификата должен содержать только цифры")
        if len(value) > 27:
            raise ValueError("Серийный номер сертификата не может быть длиннее 27 символов")
        return value
    
    @validates('revoke_date')
    def validate_revoke_date(self, key, value):
        if value and value > datetime.now().date():
            raise ValueError("Дата отзыва сертификата не может быть в будущем")
        return value
    
    # @validates('revoke_reason')
    # def validate_revoke_reason(self, key, value):
    #     if value is not None:
    #         valid_values = {reason.value for reason in CRLReasonCode}
    #         if value not in valid_values:
    #             raise ValueError(
    #                 f"Причина отзыва должна быть одним из: {[reason.value for reason in CRLReasonCode]}"
    #             )
    #     return value

    @validates('revoke_reason')
    def validate_revoke_reason(self, key, value):
        if value is not None:
            valid_names = {reason.name for reason in CRLReasonCode}  # {"unspecified", "keyCompromise", ...}
            if value not in valid_names:
                raise ValueError(
                    f"Причина отзыва должна быть одной из: {valid_names}"
                )
        return value
    
    # @validates('invalidity_date')
    # def validate_revoke_date(self, key, value):
    #     if value and value > datetime.now().date():
    #         raise ValueError("Дата признания сертификата недействительным не может быть в будущем")
    #     return value
    

    @validates('source_serial_number')
    def validate_source_serial_number(self, key, value):
        if not value.isdigit():
            raise ValueError("Серийный номер самоподписанного сертификата должен содержать только цифры")
        if len(value) > 27:
            raise ValueError("Серийный номер самоподписанного сертификата не может быть длиннее 20 символов")
        return value

    @validates('is_revoked')
    def validate_is_revoked(self, key, value):
        if value and not self.revoke_date:
            raise ValueError("Дата отзыва обязательна при отзыве сертификата")
        return value

    # Ограничения уровня БД
    __table_args__ = (
    CheckConstraint(
        "serial_number ~ '^[0-9]+$'",
        name="ck_certificates_serial_number_digits"
    ),
    CheckConstraint(
        "revoke_date <= CURRENT_DATE",
        name="ck_certificates_revoke_date_not_future"
    ),
    # CheckConstraint(
    #         "revoke_reason IS NULL OR revoke_reason IN (0, 1, 2, 3, 4, 5, 6, 8)",
    #         name="ck_certificates_valid_revoke_reason"
    #     ),
    CheckConstraint(
            "revoke_reason IS NULL OR revoke_reason IN ('unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL')",
            name="ck_certificates_valid_revoke_reason"
        ),
    # CheckConstraint(
    #     "invalidity_date <= CURRENT_DATE",
    #     name="ck_certificates_invalidity_date_not_future"
    # ),
    CheckConstraint(
        "source_serial_number ~ '^[0-9]+$'",
        name="ck_certificates_source_serial_number_digits"
    ),
    CheckConstraint(
        "(is_revoked = false) OR (is_revoked = true AND revoke_date IS NOT NULL AND invalidity_date IS NOT NULL)",
        name="ck_certificates_revoke_date_required_when_revoked"
    ),
)

def get_engine():
    config = ConfigParser()
    try:
        if not config.read('/etc/myapp/db.env'):
            raise ValueError("Не удалось прочитать конфигурационный файл")

        return create_engine(
            f"postgresql://{config['postgresql']['DB_USER']}:{config['postgresql']['DB_PASS']}@"
            f"{config['postgresql']['DB_HOST']}:{config['postgresql']['DB_PORT']}/"
            f"{config['postgresql']['DB_NAME']}"
        )
    except Exception as e:
        print(f"Ошибка подключения к БД: {str(e)}")
        raise

engine = get_engine()
Session = sessionmaker(bind=engine)