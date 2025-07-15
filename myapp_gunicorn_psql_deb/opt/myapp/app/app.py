from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for
import os
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from configparser import ConfigParser
import logging
from logging.handlers import RotatingFileHandler
import sys
from datetime import datetime, timezone,  timedelta
from asn1_parser.cert_parse import CertsAsn1
from asn1_parser.asn1_parse import bytes_to_pem, generate_serial_num
from asn1_parser.models.RootCert import RootCert, restore_root_cert
from asn1_parser.models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN
from asn1_parser.models.CertTemplate import CertTemplate, RDNTemplate
from asn1_parser.models.RevokedCertificates import RevokedCertificates, CRLReasonCode
from asn1_parser.models.AlgParams import AlgTypes
from threading import Lock
from pathlib import Path
from io import BytesIO
import subprocess
from db.DatabaseManager import DatabaseManager

# curl -X POST   -F "file=@./full.p10"   http://localhost/api/create_certificate_p10   --output received_cert.pem
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
CERTSASN1 = 'CertsAsn1'


def setup_logging():
    logger = logging.getLogger(__name__)
    
    # Убедимся, что логгер не дублирует сообщения
    logger.propagate = False
    
    logger.setLevel(logging.DEBUG)
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
            log_file.touch(mode=0o666)
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
        handlers = [file_handler, console_handler]
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
logger = setup_logging()
app = Flask(__name__)
app.config['ROOT_CERT_INIT_LOCK'] = Lock()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db_manager = DatabaseManager(logger)

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



'''------------------------------- ПРОВЕРКА НА СУЩЕСТВ-НИЕ КОРНЕВОГО СЕРТИФИКАТА ПРИ ЗАПУСКЕ ПРИЛОЖЕНИЯ--------------------------------'''
def init_root_cert():
    cert_path = Path('./root_certs/root_cert.der')
    
    # Добавим явное сообщение о начале инициализации
    logger.info("Checking existance of root certificate...")
    
    with app.config['ROOT_CERT_INIT_LOCK']:
        rootCert = None
        if cert_path.exists():
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    
                    if cert_data is None:
                        rootCert = None 
                    else:
                        rootCert = restore_root_cert(cert_data)
                        logger.info("Existing root certificate was successfully restored")
            except Exception as e:
                logger.error(f"Error while loading existing root certificate: {e}")
        else:
            logger.info("No existing root certificate was found at %s", cert_path)

        app.config[CERTSASN1] = CertsAsn1(rootCert=rootCert)

'''-----------------------------------------------------------------------------------------------------------------------------'''

def find_serial_number(number, db_manager):
    # conn = get_db_connection()
    # cursor = conn.cursor()
    # number_str = str(number)
    # while True:
    #     cursor.execute(
    #         "SELECT 1 FROM certificates WHERE serial_number = %s",
    #         (number_str,)
    #     )
        
    #     if not cursor.fetchone():
    #         conn.close()
    #         return number
        
    #     number = generate_serial_num()
    #     number_str = str(number)
    
    # conn.close()
    # return number
    with db_manager.get_cursor() as cursor:
        number_str = str(number)
        while True:
            cursor.execute(
                "SELECT 1 FROM certificates WHERE serial_number = %s",
                (number_str,)
            )
            
            if not cursor.fetchone():
                return number
            
            number = generate_serial_num()
            number_str = str(number)
        
    return number

'''------------------------------------------------ РАБОТА С БД -------------------------------------------------------------------'''
# def get_db_config():
#     config = ConfigParser()
#     try:
#         config.read('../../../etc/myapp/db.env')
#         if not config.has_section('postgresql'):
#             raise ValueError("Section [postgresql] not found in config file")
            
#         return {
#             'host': config.get('postgresql', 'DB_HOST'),
#             'port': config.getint('postgresql', 'DB_PORT'),  
#             'database': config.get('postgresql', 'DB_NAME'),
#             'user': config.get('postgresql', 'DB_USER'),
#             'password': config.get('postgresql', 'DB_PASS')
#         }
#     except Exception as e:
#         logger.error(f"Error reading data bases's configuration file: {str(e)}")
#         raise

# def get_db_connection():
#     config = get_db_config()
#     try:
#         conn = psycopg2.connect(
#             host=config['host'],
#             port=config['port'],
#             dbname=config['database'],
#             user=config['user'],
#             password=config['password'],
#             connect_timeout=10  # Таймаут подключения 10 секунд
#         )
#         logger.info("Successfully connected to data base")
#         return conn
#     except psycopg2.Error as e:
#         logger.error(f"Data base connection error: {str(e)}")
#         raise

def get_revoked_certificates(db_manager):
    # conn = get_db_connection()
    # cursor = conn.cursor()
    # cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE")
    # revoked_certificates = []
    # for row in cursor.fetchall():
    #     serialNumber=int(row[0])
    #     revocationDate=row[1]
    #     if (len(row[2]) > 0 ):
    #         crlReasonCode=CRLReasonCode[row[2]]
    #     else:
    #         clReasonCode=CRLReasonCode.unspecified
    #     invalidityDate=row[3]
    #     revoked_certificates.append(RevokedCertificates(serialNumber=serialNumber, revocationDate=revocationDate,
    #                               crlReasonCode=crlReasonCode, invalidityDate = invalidityDate))
    #     # s(
    #     #     serialNumber=int(row[0]),  
    #     #     revocationDate=row[1],
    #     #     crlReasonCode=CRLReasonCode.cACompromise,   # TODO брать из БД (CRLReasonCode - это enum)
    #     #     invalidityDate=datetime(1900, 7, 10, tzinfo=timezone.utc)   # TODO брать из БД. Дата признания недействительным
        
    # conn.close()

    # #ОТЛАДОЧНАЯ ПЕЧАТЬ
    # print("Revoked certificates:", len(revoked_certificates))
    # for cert in revoked_certificates:
    #     print(f"Serial: {cert.serialNumber}, Revocation Date: {cert.revocationDate}, Reason:{cert.crlReasonCode.name}, inv:{cert.invalidityDate}")
    
    
    # return revoked_certificates

    revoked_certificates = []
    with db_manager.get_cursor() as cursor:
        cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE")
        
        for row in cursor.fetchall():
            serialNumber = int(row[0])
            revocationDate = row[1]
            crlReasonCode = CRLReasonCode[row[2]] if row[2] else CRLReasonCode.unspecified
            invalidityDate = row[3]
            
            revoked_certificates.append(
                RevokedCertificates(
                    serialNumber=serialNumber,
                    revocationDate=revocationDate,
                    crlReasonCode=crlReasonCode,
                    invalidityDate=invalidityDate
                )
            )
    
    #logger.debug(f"Revoked certificates count: {len(revoked_certificates)}")
    #ОТЛАДОЧНАЯ ПЕЧАТЬ
    # for cert in revoked_certificates:
    #     logger.debug(f"Serial: {cert.serialNumber}, Revocation Date: {cert.revocationDate}, Reason:{cert.crlReasonCode.name}, inv:{cert.invalidityDate}")
    
    
    return revoked_certificates

def insert_to_db(serial_number, source_serial_number, db_manager):
    # try:
    #     conn = get_db_connection()
    #     cursor = conn.cursor()
        
    #     cursor.execute(
    #         """INSERT INTO certificates 
    #         VALUES (%s, false, null, null, null, %s)""",
    #         (serial_number, source_serial_number)
    #     )
    #     conn.commit()
    #     return True  
    # except Exception as e:
    #     logger.error(f"Error inserting certificate to database: {str(e)}")
    #     return False  
    # finally:
    #     if 'conn' in locals():
    #         conn.close()

    try:
        with db_manager.get_cursor() as cursor:
            cursor.execute(
                """INSERT INTO certificates 
                VALUES (%s, false, null, null, null, %s)""",
                (serial_number, source_serial_number)
            )
        return True
    except Exception as e:
        logger.error(f"Error while inserting certificate to database: {str(e)}")
        return False

'''------------------------------------------------------------------------------------------------------'''
# главная страница
@app.route('/')
def index():
    return render_template('index.html')

'''------------------------------------------------ СОЗДАНИЕ САМОПОДПИСНОГО СЕРТИФИКАТА -------------------------------------'''
@app.route('/create-selfsigned-certificate')
def create_certificate_page():
    return render_template('create_selfsigned_certificate.html')

@app.route('/api/create-selfsigned-certificate', methods=['POST'])
def create_selfsigned_certificate():
    try:
        req_data = request.form # объект, который содержит данные формы, отправленные POST-запросом (аналог словаря python)
        
        # организация
        common_name = req_data.get('common_name', '').strip()
        org_name = req_data.get('org_name', '').strip()
        
        org_country = req_data.get('org_country', '').strip()
        org_region = req_data.get('org_region', '').strip()
        org_locality = req_data.get('org_locality', '').strip()
        org_address = req_data.get('org_address', '').strip()
        
        # сотрудник
        surname = req_data.get('surname', '').strip()
        given_name = req_data.get('name', '').strip()
        org_unit_name = req_data.get('department', '').strip()
        title = req_data.get('position', '').strip()
        
        # дополнительные поля
        algorithm_value = request.form.get('algorithm')
        alg_type = AlgTypes[algorithm_value]
        beg_date = request.form.get('beg_validity_date')
        end_date = request.form.get('end_validity_date')
        beg_date = datetime.strptime(beg_date, '%Y-%m-%d').date()  # TODO проверка даты
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
        certsAsn1 = app.config[CERTSASN1]
        prdn = ParamsRDN(surname= surname, givenName=given_name, 
                            organizationalUnitName=org_unit_name, title=title,
                            commonName=common_name, organizationName=org_name,
                            countryName=org_country, stateOrProvinceName=org_region, 
                            streetAddress=org_address, localityName=org_locality)
        
        p = ParamsSelfSignedCert(alg_type=alg_type, 
                                beg_validity_date=beg_date,
                                end_validity_date=end_date,
                                paramsRDN=prdn)

        serial_num = generate_serial_num() 
        serial_num = find_serial_number(serial_num, db_manager)  # проверка на уникальность серийного номера
        cert_bytes, private_key, password = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
        #logger.info(certsAsn1.rootCert)
        with open(ROOT_CERT_PATH, 'wb') as f:
            f.write(cert_bytes)
        # ENTRY_NAME = "cert_password"  # Название записи
        # # Команда для добавления пароля
        # cmd = [
        #     "keepassxc-cli", "add",
        #     "--quiet",
        #     KEEPASS_DB_PATH,
        #     ENTRY_NAME
        # ]

        # try:
        #     subprocess.run(
        #         cmd,
        #         input=f"{password}\nprac2025\n",  # Сначала пароль записи, затем мастер-пароль
        #         text=True,
        #         check=True
        #     )
        #     logger.info("Пароль успешно сохранён!")
        # except subprocess.CalledProcessError as e:
        #     logger.error(f"Ошибка: {e.stderr}")
        logger.info("Root self signed certificate was successfully created")
        return redirect(url_for('selfsigned_certificate_created'))

    except Exception as e:
        logger.error(f"Error while creating selfsigned certificate: {str(e)}")
        return render_template('error.html', error=str(e)), 500

    # except Exception as e:
    #     logger.error(f"Error while creating selfsigned certificate: {str(e)}")
    #     return jsonify({
    #         "error": "Error while creating selfsigned certificate",
    #         "details": str(e)
    #     }), 500
    
@app.route('/certificate-created')
def selfsigned_certificate_created():
    certsAsn1 = app.config[CERTSASN1]
    if certsAsn1.rootCert is None:
        return redirect(url_for('create_certificate_page'))
    
    return render_template('selfsigned_certificate_created.html',
                         serial_num=certsAsn1.rootCert.serial_num)

@app.route('/download-certificate') # Только для самоподписанного!!!
def download_certificate():
    certsAsn1 = app.config[CERTSASN1]
    if certsAsn1.rootCert is None:
        return "Self signed certificate not found", 404
    
    return send_file(
        BytesIO(certsAsn1.rootCert.cert_bytes),
        mimetype='application/x-x509-ca-cert', # указывает тип содержимого
        as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
        # download_name=f'certificate_{cert_data["serial_num"]}.der'
        download_name="certificate.der"
    )

@app.route('/download-private-key')
def download_private_key():
    certsAsn1 = app.config[CERTSASN1]
    if certsAsn1.rootCert is None or certsAsn1.rootCert.private_key is None:
        return "Private key not found", 404
    
    key_file = BytesIO(certsAsn1.rootCert.private_key) 
    return send_file(
        key_file,
        as_attachment=True,    
        #download_name=f'private_key{cert_data["serial_num"]}.key',
        download_name="private.key",
        mimetype="application/octet-stream"  # Указывает, что это бинарный файл
    )

@app.route('/show-password')
def show_password():
    certsAsn1 = app.config[CERTSASN1]
    if certsAsn1.rootCert is None or certsAsn1.rootCert.password is None:
        return "Password not found", 404
    
    return render_template('show_password.html', password=certsAsn1.rootCert.password)

'''------------------------------------------------ ОТЗЫВ СЕРТИФИКАТОВ ------------------------------------'''
@app.route('/revoke-certificate')
def revoke_certificate_page():
    # try:
    #     conn = get_db_connection()
    #     cursor = conn.cursor(cursor_factory=DictCursor)
        
    #     cursor.execute("SELECT * FROM certificates")
    #     certificates = cursor.fetchall()
        
    #     cursor.close()
    #     conn.close()

    #     certs_data = []
    #     for cert in certificates:
    #         certs_data.append({
    #             'serial_number': cert['serial_number'],
    #             'status': "Отозван" if cert['is_revoked'] else "Не отозван",
    #             'revoke_date': cert['revoke_date'].strftime('%Y-%m-%d') if cert['revoke_date'] else None,
    #             'invalidity_date': cert['invalidity_date'].strftime('%Y-%m-%d') if cert['revoke_date'] else None,
    #             'revoke_reason': cert['revoke_reason'],
    #             'source_serial_number': cert['source_serial_number']
    #             #'send_to_ocsp': "Да" if cert['send_to_ocsp'] else "Нет"
    #         })
        
    #     return render_template('revoke_certificate.html', certificates=certs_data)
    
    # except Exception as e:
    #     return render_template('error.html', error=str(e)), 500
    try:
        revoked_certs = []
        with db_manager.get_cursor() as cursor:
            cursor.execute("SELECT serial_number, is_revoked, revoke_date, invalidity_date, revoke_reason, source_serial_number FROM certificates")
            certificates = cursor.fetchall()
            
            for cert in certificates:
                revoked_certs.append({
                    'serial_number': cert[0],  # serial_number
                    'status': "Отозван" if cert[1] else "Не отозван",  # is_revoked
                    'revoke_date': cert[2].strftime('%Y-%m-%d') if cert[2] else None,  # revoke_date
                    'invalidity_date': cert[3].strftime('%Y-%m-%d') if cert[2] else None,  # invalidity_date (исправлена проверка на revoke_date)
                    'revoke_reason': cert[4],  # revoke_reason
                    'source_serial_number': cert[5]  # source_serial_number
                })
        
        return render_template('revoke_certificate.html', certificates=revoked_certs)

    except Exception as e:
        return render_template('error.html', error=str(e)), 500



@app.route('/api/revoke-certificate', methods=['POST'])
def revoke_certificate():
    # try:
    #     data = request.get_json()
    #     if not data or 'certificates' not in data:
    #         return jsonify({"error": "Неверный формат данных"}), 400
        
    #     certs_to_revoke = data['certificates']
    #     if not certs_to_revoke:
    #         return jsonify({"error": "Не выбраны сертификаты для отзыва"}), 400
        
    #     for cert_data in certs_to_revoke:
    #         if not cert_data.get('invalidity_date'):
    #             return jsonify({
    #                 "error": f"Для сертификата {cert_data['serial_number']} не указана дата признания недействительным",
    #                 "serial_number": cert_data['serial_number']
    #             }), 400
        
    #     conn = get_db_connection()
    #     cursor = conn.cursor()
    #     try:
    #         for cert_data in certs_to_revoke:
    #             cursor.execute(
    #                 """UPDATE certificates 
    #                 SET is_revoked = TRUE, 
    #                     revoke_date = NOW(), 
    #                     invalidity_date = %s,
    #                     revoke_reason = %s
    #                 WHERE serial_number = %s""",
    #                 (
    #                     cert_data['invalidity_date'],
    #                     cert_data.get('revoke_reason', 'unspecified'),  
    #                     cert_data['serial_number']
    #                 )
    #             )
            
    #         conn.commit()
    #         return jsonify({
    #             "status": "success",
    #             "message": f"Успешно отозвано {len(certs_to_revoke)} сертификатов"
    #         })
            
    #     except Exception as e:
    #         conn.rollback()
    #         return jsonify({"error": f"Ошибка базы данных: {str(e)}"}), 500
    #     finally:
    #         cursor.close()
    #         conn.close()
    
    # except Exception as e:
    #     return jsonify({"error": str(e)}), 500
    try:
        data = request.get_json()
        if not data or 'certificates' not in data:
            return jsonify({"error": "Неверный формат данных"}), 400
        
        certs_to_revoke = data['certificates']
        if not certs_to_revoke:
            return jsonify({"error": "Не выбраны сертификаты для отзыва"}), 400
        
        for cert_data in certs_to_revoke:
            if not cert_data.get('invalidity_date'):
                return jsonify({
                    "error": f"Для сертификата {cert_data['serial_number']} не указана дата признания недействительным",
                    "serial_number": cert_data['serial_number']
                }), 400
        
        with db_manager.get_cursor() as cursor:
            for cert_data in certs_to_revoke:
                cursor.execute(
                    """UPDATE certificates 
                    SET is_revoked = TRUE, 
                        revoke_date = NOW(), 
                        invalidity_date = %s,
                        revoke_reason = %s
                    WHERE serial_number = %s""",
                    (
                        cert_data['invalidity_date'],
                        cert_data.get('revoke_reason', 'unspecified'),
                        cert_data['serial_number']
                    )
                )
            
            return jsonify({
                "status": "success",
                "message": f"Успешно отозвано {len(certs_to_revoke)} сертификатов"
            })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
'''------------------------------------------------ СОЗДАНИЕ СЕРТИФИКАТА ПО ЗАПРОСУ -------------------------------------'''
# прием запроса на создание сертификата (файла .p10)
@app.route('/api/create_certificate_p10', methods=['POST'])
def create_certificate_p10():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400 # файл отсутствует в запросе
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    
    try:
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
        
        # сохранение полученного файла p10
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, 'r') as pem_file:
            pem_csr = pem_file.read()

        certsAsn1 = app.config[CERTSASN1]
        
        rdn_template = RDNTemplate()    
        # TODO заполнить поля rdn_template на основе файла-шаблона от пользователя (если файл не поступил, то поля не трогаем)
        rdn_template.surname = rdn_template.givenName = rdn_template.streetAddress = False  
        cert_template = CertTemplate(rdn_template)  # пока не трогаем

        # TODO интерфейс для отправки запроса p10
        serial_num = find_serial_number(generate_serial_num(), db_manager)
        beg_validity_date = datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc)  # TODO interface
        end_validity_date = datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc)  # TODO interface
        cert_bytes = certsAsn1.create_cert(serial_num=serial_num, 
                                       beg_validity_date=beg_validity_date,
                                       end_validity_date=end_validity_date,
                                       cert_template=cert_template, 
                                       pem_csr=pem_csr)
        
        rc = insert_to_db(serial_num, certsAsn1.rootCert.serial_num, db_manager) 
        if not rc:
            raise Exception("Не удалось добавить сертификат в БД")
        res_filename =  f"./created_files/res{serial_num}.pem"
        with open(res_filename, 'w') as f:
            f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ
        
        return send_file(
            res_filename,
            as_attachment=True,
            download_name=res_filename , 
            mimetype='application/x-pem-file'
        )
    # TODO отдельно обработать ошибку ErrNoRootCert
    except Exception as e:
        logger.error(f"Error while sending .pem file: {str(e)}")
        return jsonify({f"Error while sending .pem file: {str(e)}"}), 500 
    

# @app.route('/api/create_certificate_p10', methods=['POST'])
# def create_certificate_p10():
#     # Проверка наличия файла
#     if 'file' not in request.files:
#         return jsonify({"error": "No file provided"}), 400
    
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({"error": "Empty filename"}), 400
    
#     # Проверка шаблона
#     template = request.form.get('template')
#     if not template:
#         return jsonify({"error": "No template selected"}), 400
    
#     try:
#         # Сохранение .p10 во временную папку
#         upload_dir = os.path.join(app.root_path, 'uploads')
#         os.makedirs(upload_dir, exist_ok=True)
        
#         filename = secure_filename(file.filename)
#         file_path = os.path.join(upload_dir, filename)
#         file.save(file_path)
        
#         # Чтение .p10
#         with open(file_path, 'r') as f:
#             pem_csr = f.read()
        
#         # Обработка шаблона (пример)
#         if template == 'user':
#             rdn_template = RDNTemplate(surname=True, givenName=True)
#         elif template == 'server':
#             rdn_template = RDNTemplate(organization=True, commonName=True)
#         else:
#             rdn_template = RDNTemplate()  # Дефолтный
        
#         cert_template = CertTemplate(rdn_template)
        
#         # Генерация сертификата
#         serial_num = generate_serial_num()
#         beg_date = datetime.now(timezone.utc)
#         end_date = datetime(beg_date.year + 1, beg_date.month, beg_date.day, tzinfo=timezone.utc)
        
#         cert_bytes = certsAsn1.create_cert(
#             serial_num=serial_num,
#             beg_validity_date=beg_date,
#             end_validity_date=end_date,
#             cert_template=cert_template,
#             pem_csr=pem_csr
#         )
        
#         # Сохранение сертификата
#         cert_filename = f"cert_{serial_num}.pem"
#         cert_path = os.path.join(upload_dir, cert_filename)
        
#         with open(cert_path, 'wb') as f:
#             f.write(cert_bytes)
        
#         # Отправка файла пользователю
#         return send_file(
#             cert_path,
#             as_attachment=True,
#             download_name=cert_filename,
#             mimetype='application/x-pem-file'
#         )
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

def create_app_folders():
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
            logger.error(f"Error while creating directory {folder}: {str(e)}")
            raise


def initialize_application():
    try:
        logger.info("Application starting...")
        current_dir = os.getcwd()
        logger.info(f"current_dir: {current_dir}")
        create_app_folders()

        required_templates = ['index.html', 'revoke_certificate.html', 'create_selfsigned_certificate.html']
        for template in required_templates:
            if not os.path.exists(f'./templates/{template}'):
                logger.error(f"Шаблон {template} не найден в директории templates")

        init_root_cert()

       # get_revoked_certificates(db_manager)  # отладочный вывод

        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        sys.exit(1)


initialize_application()

if __name__ == '__main__':
    # Локальный запуск (только для запуска через python3
    app.run(host='0.0.0.0', port=5000, debug=True)







    '''
if __name__ == '__main__':
    try:
        logger.info("Application starting...")
        create_app_folders()
        required_templates = ['index.html', 'revoke_certificate.html', 'create_selfsigned_certificate.html']
        for template in required_templates:
            if not os.path.exists(f'./templates/{template}'):
                logger.error(f"Шаблон {template} не найден в директории templates")

        init_root_cert()
        # try:
        #     conn = get_db_connection()
        #     conn.close()
        #     logger.info("Database connection test successful")
        # except Exception as e:
        #     logger.error(f"Database connection test failed: {str(e)}")
        get_revoked_certificates(db_manager)
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)
    '''
