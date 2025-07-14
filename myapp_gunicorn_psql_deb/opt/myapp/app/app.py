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
from cert_parse import CertsAsn1
from asn1_parse import bytes_to_pem, generate_serial_num
from models.RootCert import RootCert, restore_root_cert
from models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN
from models.CertTemplate import CertTemplate, RDNTemplate
from models.RevokedCertificates import RevokedCertificates, CRLReasonCode
from threading import Lock
from pathlib import Path
from io import BytesIO
import subprocess


app = Flask(__name__)
app.config['ROOT_CERT_INIT_LOCK'] = Lock()
app.config['ROOT_CERT'] = None  

UPLOAD_FOLDER = 'uploads' #дир-рия для хранения загруженных файлов (полученных из запроса файлов)
CREATED_FILES_FOLDER = 'created_files'
ROOT_CERT_FOLDER = 'root_certs'  # для корневых сертификатов
ROOT_CERT_PATH = os.path.join(ROOT_CERT_FOLDER, 'root_cert.der')
ALLOWED_EXTENSIONS = {'p10'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
KEEPASS_DB_PATH = "/var/lib/myapp/secrets.kdbx"  # Путь к базе

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



log_path = Path('/var/log/myapp/app.log')
fallback_path = Path.home() / 'myapp_logs/app.log'

# Пытаемся использовать основной путь
try:
    log_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    log_path.touch(mode=0o644, exist_ok=True)
    current_log = log_path
except (PermissionError, OSError):
    # Fallback на домашнюю директорию
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    fallback_path.touch(exist_ok=True)
    current_log = fallback_path
    logging.warning(f"Using fallback log location: {fallback_path}")

# Настройка обработчиков
handlers = [
    logging.StreamHandler(sys.stdout),
    RotatingFileHandler(
        str(current_log),
        maxBytes=1_000_000,
        backupCount=3,
        encoding='utf-8'
    )
]

# Инициализация логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers
)

logger = logging.getLogger(__name__)


'''------------------------------- ПРОВЕРКА НА СУЩЕСТВ-НИЕ КОРНЕВОГО СЕРТИФИКАТА ПРИ ЗАПУСКЕ ПРИЛОЖЕНИЯ--------------------------------'''
# def init_root_cert():
#     cert_path = Path('./root_certs/root_cert.der')
    
#     with app.config['ROOT_CERT_INIT_LOCK']:
#         if cert_path.exists():

#             try:
#                 with open(cert_path, 'rb') as f:
#                     cert_data = f.read()
#                     app.config['ROOT_CERT'] = restore_root_cert(cert_data)
#                     logger.info("Existing root certificate was restored")
#             except Exception as e:
#                 logger.error(f"Error loading cert: {e}")
#                 app.config['ROOT_CERT'] = None
#         else:
#             logger.info("There is no existing root certificate")
#             # app.config['ROOT_CERT'] = RootCert(
#             #     serial_num=1,
#             #     issuer_rdn_bytes=b'default_issuer',  # Замените реальными данными
#             #     alg_type='RSA',
#             #     beg_validity_date=datetime.now(),
#             #     end_validity_date=datetime(2025, 12, 31),
#             #     public_key=b'default_public_key'  # Замените реальным ключом
#             # )
#             # print("New root certificate created")
            
#             app.config['ROOT_CERT'] = None
def init_root_cert():
    cert_path = Path('./root_certs/root_cert.der')
    
    # Добавим явное сообщение о начале инициализации
    logger.info("Checking existance of root certificate...")
    
    with app.config['ROOT_CERT_INIT_LOCK']:
        if cert_path.exists():
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                    app.config['ROOT_CERT'] = restore_root_cert(cert_data)
                    logger.info("Existing root certificate was successfully restored")
                    # Добавим подробную информацию о сертификате
                    if app.config['ROOT_CERT']:
                        logger.info(f"Root certificate was restored successfully")
            except Exception as e:
                logger.error(f"Error loading certificate: {e}")
                app.config['ROOT_CERT'] = None
        else:
            logger.warning("No existing root certificate found at %s", cert_path)
            app.config['ROOT_CERT'] = None

'''-----------------------------------------------------------------------------------------------------------------------------'''

def find_serial_number(number):
    conn = get_db_connection()
    cursor = conn.cursor()
    number_str = str(number)
    while True:
        cursor.execute(
            "SELECT 1 FROM certificates WHERE serial_number = %s",
            (number_str,)
        )
        
        if not cursor.fetchone():
            conn.close()
            return number
        
        number = generate_serial_num()
        number_str = str(number)
    
    conn.close()
    return number


'''------------------------------------------------ РАБОТА С БД -------------------------------------------------------------------'''
def get_db_config():
    config = ConfigParser()
    try:
        config.read('../../../etc/myapp/db.env')
        if not config.has_section('postgresql'):
            raise ValueError("Section [postgresql] not found in config file")
            
        return {
            'host': config.get('postgresql', 'DB_HOST'),
            'port': config.getint('postgresql', 'DB_PORT'),  
            'database': config.get('postgresql', 'DB_NAME'),
            'user': config.get('postgresql', 'DB_USER'),
            'password': config.get('postgresql', 'DB_PASS')
        }
    except Exception as e:
        logger.error(f"Error reading data bases's configuration file: {str(e)}")
        raise

def get_db_connection():
    config = get_db_config()
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            dbname=config['database'],
            user=config['user'],
            password=config['password'],
            connect_timeout=10  # Таймаут подключения 10 секунд
        )
        logger.info("Successfully connected to data base")
        return conn
    except psycopg2.Error as e:
        logger.error(f"Data base connection error: {str(e)}")
        raise

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
        
        # # дополнительные поля
        # snils = req_data.get('snils', '').strip()
        # email = req_data.get('email', '').strip()

        certsAsn1 = CertsAsn1()
        prdn = ParamsRDN(surname= surname, givenName=given_name, 
                            organizationalUnitName=org_unit_name, title=title,
                            commonName=common_name, organizationName=org_name,
                            countryName=org_country, stateOrProvinceName=org_region, 
                            streetAddress=org_address, localityName=org_locality)
        current_date_utc = datetime.now(timezone.utc)
        next_year_date = datetime.now(timezone.utc) + timedelta(days=365)

        p = ParamsSelfSignedCert(alg_type="b", 
                                beg_validity_date=current_date_utc,
                                end_validity_date=next_year_date,
                                paramsRDN=prdn)

        serial_num = generate_serial_num() 
        serial_num = find_serial_number(serial_num)  # проверка на уникальность серийного номера
        cert_bytes, private_key, password = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
        logger.info(certsAsn1.rootCert)
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

        # app.config['ROOT_CERT'] = RootCert(
        #         serial_num=serial_num,
        #         issuer_rdn_bytes=prdn, #  ?????????????????????
        #         alg_type="b",
        #         beg_validity_date=current_date_utc,
        #         end_validity_date=next_year_date,
        #         public_key= private_key # ?????????????????
        #     )
        

        app.config['CERT_DATA'] = {
            'password': password,
            'private_key': private_key,
            'cert_bytes': cert_bytes,
            'serial_num': serial_num
        }

        logger.info("Root self signed certificate was successfully created")
        return redirect(url_for('selfsigned_certificate_created'))

    except Exception as e:
        logger.error(f"Error while creating selfsigned certificate: {str(e)}")
        return render_template('error.html', error=str(e)), 500

    except Exception as e:
        logger.error(f"Error while creating selfsigned certificate: {str(e)}")
        return jsonify({
            "error": "Error while creating selfsigned certificate",
            "details": str(e)
        }), 500
    
@app.route('/certificate-created')
def selfsigned_certificate_created():
    cert_data = app.config.get('CERT_DATA', {})
    if not cert_data:
        return redirect(url_for('create_certificate_page'))
    
    return render_template('selfsigned_certificate_created.html',
                         serial_num=cert_data['serial_num'])



@app.route('/download-certificate')
def download_certificate():
    cert_data = app.config.get('CERT_DATA')
    if not cert_data or 'cert_bytes' not in cert_data:
        return "Self signed certificate not found", 404
    
    return send_file(
        BytesIO(cert_data['cert_bytes']),
        mimetype='application/x-x509-ca-cert', # указывает тип содержимого
        as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
        download_name=f'certificate_{cert_data["serial_num"]}.der'
    )

@app.route('/download-private-key')
def download_private_key():
    cert_data = app.config.get('CERT_DATA')
    if not cert_data or 'private_key' not in cert_data:
        return "Private key not found", 404
    

    key_file = BytesIO(cert_data['private_key']) 
    
    return send_file(
        key_file,
        as_attachment=True,    
        download_name=f'private_key{cert_data["serial_num"]}.key',
        mimetype="application/octet-stream"  # Указывает, что это бинарный файл
    )

    # return send_file(
    #     BytesIO(cert_data['private_key']),
    #     mimetype='application/x-pem-file',
    #     as_attachment=True,
    #     download_name=f'private_key_{cert_data["serial_num"]}.pem'
    # )

@app.route('/show-password')
def show_password():
    cert_data = app.config.get('CERT_DATA')
    if not cert_data or 'password' not in cert_data:
        return "Password not found", 404
    
    return render_template('show_password.html', password=cert_data['password'])

'''------------------------------------------------ ОТЗЫВ СЕРТИФИКАТОВ ------------------------------------'''
@app.route('/revoke-certificate')
def revoke_certificate_page():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        cursor.execute("SELECT * FROM certificates")
        certificates = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # преобр. данные для отображения
        certs_data = []
        for cert in certificates:
            certs_data.append({
                'serial_number': cert['serial_number'],
                'status': "Отозван" if cert['is_revoked'] else "Не отозван",
                'revoke_date': cert['revoke_date'].strftime('%Y-%m-%d') if cert['revoke_date'] else None,
                'send_to_ocsp': "Да" if cert['send_to_ocsp'] else "Нет"
            })
        
        return render_template('revoke_certificate.html', certificates=certs_data)
    
    except Exception as e:
        return render_template('error.html', error=str(e)), 500


@app.route('/api/revoke-certificate', methods=['POST'])
def revoke_certificate():
    try:
        # Получаем список сертификатов для отзыва из формы
        certs_to_revoke = request.form.getlist('revoke_cert')
        
        if not certs_to_revoke:
            return jsonify({"error": "Не выбраны сертификаты для отзыва"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Обновляем статус выбранных сертификатов
            for cert_serial in certs_to_revoke:
                cursor.execute(
                    "UPDATE certificates SET is_revoked = TRUE, revoke_date = NOW() WHERE serial_number = %s",
                    (cert_serial,)
                )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                "status": "success",
                "message": f"Успешно отозвано {len(certs_to_revoke)} сертификатов"
            })
        
        except Exception as e:
            conn.rollback()
            raise e
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
def get_revoked_certificates():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT serial_number, revoke_date FROM certificates WHERE is_revoked = TRUE")
    # revoked_certificates = [
    #     RevokedCertificates(
    #         serialNumber=int(row[0]),  
    #         revocationDate=row[1]     
    #     )
    #     for row in cursor.fetchall()
    # ]
    # conn.close()

    # print("Revoked certificates:")
    # for cert in revoked_certificates:
    #     print(f"Serial: {cert.serialNumber}, Revocation Date: {cert.revocationDate}")
    
    # return revoked_certificates



'''------------------------------------------------ СОЗДАНИЕ СЕРТИФИКАТА ПО ЗАПРОСУ -------------------------------------'''
# прием запроса на создание сертификата (файла .p10)
@app.route('/api/create_certificate_p10', methods=['POST'])
def create_certificate_p10():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400 # файл отсутствует в запросе
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Only .p10 files allowed"}), 400 # неподдерживаемое расширение файла
    
    try:
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
        
        # сохранение полученного файла p10
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, 'r') as pem_file:
            pem_csr = pem_file.read()

        serial_num = generate_serial_num() 
        # !!! проверка на уникальность serial_num(для этого обращение к БД: find serial_num)
        serial_num = find_serial_number(serial_num)

        #cert_bytes = create_cert(serial_num, pem_csr)
        res_filename =  f"./created_files/res{serial_num}.pem"
        with open(res_filename, 'w') as f:
            f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ

        return send_file(
        res_filename,
        as_attachment=True,
        download_name=res_filename , 
        mimetype='application/x-pem-file'
    )
    
    except Exception as e:
        return jsonify({"error": f"Failed to send PEM: {str(e)}"}), 500 
    

def create_app_folders():
    folders = [
        UPLOAD_FOLDER,
        CREATED_FILES_FOLDER,
        ROOT_CERT_FOLDER
    ]
    
    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            print(f"Папка {folder} создана или уже существует")
        except Exception as e:
            print(f"Ошибка при создании папки {folder}: {str(e)}")
            raise

if __name__ == '__main__':
    try:
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
        #get_revoked_certificates()
        
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)