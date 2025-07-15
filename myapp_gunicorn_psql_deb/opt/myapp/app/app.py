from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for
import os
import psycopg2
from psycopg2 import sql
import logging
from logging import Logger
from logging.handlers import RotatingFileHandler
import sys
from datetime import datetime, timezone,  timedelta
from asn1_parser.models.RevokedCertificates import RevokedCertificates, CRLReasonCode
from threading import Lock
from pathlib import Path
import subprocess
from storage import Storage

BASE_DIR = Path(__file__).parent
# UPLOAD_FOLDER = BASE_DIR / 'uploads'
# CREATED_FILES_FOLDER = BASE_DIR / 'created_files'
# ROOT_CERT_FOLDER = BASE_DIR / 'root_certs'
# ROOT_CERT_PATH = ROOT_CERT_FOLDER / 'root_cert.der'
# app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
UPLOAD_FOLDER = 'uploads' #дир-рия для хранения загруженных файлов (полученных из запроса файлов)
CREATED_FILES_FOLDER = 'created_files'
ROOT_CERT_FOLDER = 'root_certs'  # для корневых сертификатов
ROOT_CERT_PATH = os.path.join(ROOT_CERT_FOLDER, 'root_cert.der')
KEEPASS_DB_PATH = "/var/lib/myapp/secrets.kdbx"  # Путь к базе



def setup_logging():
    logger = logging.getLogger(__name__)
    
    # Убедимся, что логгер не дублирует сообщения
    logger.propagate = False
    
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Основной обработчик - вывод в консоль
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    try:
        # Основной путь для логов (для deb-пакета)
        log_dir = Path('/var/log/myapp')
        log_file = log_dir / 'app.log'
        
        # Fallback путь (для разработки или если нет прав на /var/log)
        fallback_log_dir = BASE_DIR / 'logs'
        fallback_log_file = fallback_log_dir / 'app.log'
        
        # Пытаемся использовать основной путь
        try:
            log_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            log_file.touch(mode=0o666, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file, maxBytes=1_000_000, backupCount=3, encoding='utf-8'
            )
            logger.info(f"Logging to system directory: {log_file}")
        except (PermissionError, OSError) as e:
            # Fallback на локальную директорию
            fallback_log_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            fallback_log_file.touch(mode=0o644, exist_ok=True)
            file_handler = RotatingFileHandler(
                fallback_log_file, maxBytes=1_000_000, backupCount=3, encoding='utf-8'
            )
            logger.warning(f"Using fallback log location: {fallback_log_file}")
        
        file_handler.setFormatter(formatter)
        handlers = [console_handler, file_handler]
    except Exception as e:
        # Если вообще ничего не получилось - используем только консоль
        handlers = [console_handler]
        logger.error(f"Failed to setup file logging: {str(e)}")
    
    # Очищаем существующие обработчики и добавляем новые
    logger.handlers.clear()
    for handler in handlers:
        logger.addHandler(handler)
    
    return logger

# Глобальная инициализация логгера
# logger = setup_logging()
# logger.info("------- 1")
# app = Flask(__name__)
# app.config['ROOT_CERT_INIT_LOCK'] = Lock()
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# logger.info("------- 2")

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.StreamHandler(sys.stdout),  # Вывод в консоль
#         RotatingFileHandler('/var/log/myapp/app.log', maxBytes=1e6, backupCount=3)  # Ротация логов
#     ]
# )
# logger = logging.getLogger(__name__)



# log_path = Path('/var/log/myapp/app.log')
# fallback_path = Path.home() / 'myapp_logs/app.log'

# try:
#     log_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
#     log_path.touch(mode=0o644, exist_ok=True)
#     current_log = log_path
# except (PermissionError, OSError):
#     fallback_path.parent.mkdir(parents=True, exist_ok=True)
#     fallback_path.touch(exist_ok=True)
#     current_log = fallback_path
#     logging.warning(f"Using fallback log location: {fallback_path}")

# handlers = [
#     logging.StreamHandler(sys.stdout),
#     RotatingFileHandler(
#         str(current_log),
#         maxBytes=1_000_000,
#         backupCount=3,
#         encoding='utf-8'
#     )
# ]

# # Инициализация логгера
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=handlers
# )

# logger = logging.getLogger(__name__)

'''------------------------------------------------ РАБОТА С БД -------------------------------------------------------------------'''

def get_revoked_certificates(storage: Storage):
    conn = storage.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE")
    revoked_certificates = []
    for row in cursor.fetchall():
        serialNumber=int(row[0])
        revocationDate=row[1]
        if (len(row[2]) > 0 ):
            crlReasonCode=CRLReasonCode[row[2]]
        else:
            clReasonCode=CRLReasonCode.unspecified
        invalidityDate=row[3]
        revoked_certificates.append(RevokedCertificates(serialNumber=serialNumber, revocationDate=revocationDate,
                                  crlReasonCode=crlReasonCode, invalidityDate = invalidityDate))
        # s(
        #     serialNumber=int(row[0]),  
        #     revocationDate=row[1],
        #     crlReasonCode=CRLReasonCode.cACompromise,   # TODO брать из БД (CRLReasonCode - это enum)
        #     invalidityDate=datetime(1900, 7, 10, tzinfo=timezone.utc)   # TODO брать из БД. Дата признания недействительным
        
    # ОТЛАДОЧНАЯ ПЕЧАТЬ
    # print("Revoked certificates:", len(revoked_certificates))
    # for cert in revoked_certificates:
    #     print(f"Serial: {cert.serialNumber}, Revocation Date: {cert.revocationDate}, Reason:{cert.crlReasonCode.name}, inv:{cert.invalidityDate}")
    return revoked_certificates

def insert_to_db(serial_number, source_serial_number, storage: Storage, logger: Logger):
    try:
        conn = storage.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO certificates 
            VALUES (%s, false, null, null, null, %s)""",
            (serial_number, source_serial_number)
        )
        conn.commit()
        return True  
    except Exception as e:
        logger.error(f"Error inserting certificate to database: {str(e)}")
        return False  
    finally:
        pass

'''------------------------------------------------------------------------------------------------------'''
def create_app_folders(logger: Logger):
    folders = [
        UPLOAD_FOLDER,
        CREATED_FILES_FOLDER,
        ROOT_CERT_FOLDER
    ]
    
    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            #logger.info(f"Папка {folder} создана или уже существует")
        except Exception as e:
            logger.error(f"Ошибка при создании папки {folder}: {str(e)}")
            raise

# from app import setup_logging, UPLOAD_FOLDER, create_app_folders, get_revoked_certificates
from storage import Storage
from asn1_parser.cert_parse import CertsAsn1
from asn1_parser.models.RootCert import restore_root_cert

from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for
from threading import Lock
import os
import sys
from pathlib import Path
from logging import Logger

CERTSASN1 = 'CertsAsn1'
LOGGER = 'logger'
STORAGE = 'storage'

appl = Flask(__name__)
appl.config['ROOT_CERT_INIT_LOCK'] = Lock()
appl.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_root_cert(logger: Logger) -> CertsAsn1:
    cert_path = Path('./root_certs/root_cert.der')
    
    # Добавим явное сообщение о начале инициализации
    logger.info("Checking existance of root certificate...")
    
    with appl.config['ROOT_CERT_INIT_LOCK']:
        rootCert = None
        if cert_path.exists():
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    
                    rootCert = restore_root_cert(cert_data)
                    
                    logger.info("Existing root certificate was successfully restored")
            except Exception as e:
                logger.error(f"Error loading existing root certificate: {e}")
        else:
            logger.info("No existing root certificate was found at %s", cert_path)

        appl.config[CERTSASN1] = CertsAsn1(rootCert=rootCert)

# if __name__ == "__main__":
logger = setup_logging()
logger.info(f"__name__ = {__name__}")
storage = Storage(logger=logger)

appl.config[LOGGER] = logger
appl.config[STORAGE] = storage

try:
    create_app_folders(logger=logger)
    current_dir = os.getcwd()
    logger.info(f"current_dir = {current_dir}")
    required_templates = ['index.html', 'revoke_certificate.html', 'create_selfsigned_certificate.html']
    for template in required_templates:
        if not os.path.exists(f'./templates/{template}'):
            logger.error(f"Шаблон {template} не найден в директории templates")
    init_root_cert(logger=logger)

    get_revoked_certificates(storage=storage)
    appl.run(host='127.0.0.1', port=5000, debug=True)
except Exception as e:
    logger.error(f"Failed to start application: {str(e)}")
    sys.exit(1)

# app.run()

from api import *
