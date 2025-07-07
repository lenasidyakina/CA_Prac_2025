from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, text 
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from configparser import ConfigParser
import os

Base = declarative_base()

# class Flower(Base):
#     __tablename__ = 'flowers'
#     id = Column(Integer, primary_key=True)
#     name = Column(String(100), nullable=False)
#     color = Column(String(50), nullable=False)

class Certificate(Base):
    __tablename__ = 'certificates'
    serial_number = Column(UUID(as_uuid=True), primary_key=True)
    is_revoked = Column(Boolean, server_default=text("false"), nullable=False)
    reason = Column(Text)

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