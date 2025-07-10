from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, text , CheckConstraint, Date
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import validates
from configparser import ConfigParser
import os
from datetime import datetime

Base = declarative_base()


class Certificate(Base):
    __tablename__ = 'certificates'
    serial_number = Column(
        String(20),  
        primary_key=True,
    )
    
    is_revoked = Column(
        Boolean,
        server_default="false",
        nullable=False
    )
    
    revoke_date = Column(Date)

    send_to_ocsp = Column(
        Boolean,
        server_default="false",
        nullable=False
    )

    source_serial_number = Column(
        String(20), nullable=False
    )
    # reason = Column(Text)
    
    # Валидация на уровне Python
    @validates('serial_number')
    def validate_serial_number(self, key, value):
        if not value.isdigit():
            raise ValueError("Серийный номер сертификата должен содержать только цифры")
        if len(value) > 20:
            raise ValueError("Серийный номер сертификата не может быть длиннее 20 символов")
        return value
    
    @validates('revoke_date')
    def validate_revoke_date(self, key, value):
        if value and value > datetime.now().date():
            raise ValueError("Дата отзыва не может быть в будущем")
        return value
    
    @validates('source_serial_number')
    def validate_source_serial_number(self, key, value):
        if not value.isdigit():
            raise ValueError("Серийный номер самоподписанного сертификата должен содержать только цифры")
        if len(value) > 20:
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
    CheckConstraint(
        "source_serial_number ~ '^[0-9]+$'",
        name="ck_certificates_source_serial_number_digits"
    ),
    CheckConstraint(
        "(is_revoked = false) OR (is_revoked = true AND revoke_date IS NOT NULL)",
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