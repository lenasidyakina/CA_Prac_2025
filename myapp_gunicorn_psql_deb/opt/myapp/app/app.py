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
from asn1_parser.cert_parse import CertsAsn1, ErrNoRootCert
from asn1_parser.asn1_parse import bytes_to_pem, generate_serial_num
from asn1_parser.models.RootCert import RootCert, restore_root_cert
from asn1_parser.models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN, ExtentionsCert
from asn1_parser.models.CertTemplate import CertTemplate, RDNTemplate, ErrParamsTemplate
from asn1_parser.models.AlgParams import AlgTypes
from threading import Lock
from pathlib import Path
from io import BytesIO
import subprocess
from db.DatabaseManager import DatabaseManager
from cert_templates.parse import file_to_dict


def setup_logging():
    logger = logging.getLogger(__name__)

    # тобы логгер не дублировал сообщения
    logger.propagate = False

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    try:
        # Основной путь для логов (для deb-пакета)
        log_dir = Path(APP_LOG_DIR)
        log_file = log_dir / APP_LOG_FILE

        # Fallback путь (для разработки или если нет прав на /var/log)
        fallback_log_dir = BASE_DIR / 'logs'
        fallback_log_file = fallback_log_dir / 'app.log'

        try:
            log_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            log_file.touch(mode=0o666)
            file_handler = RotatingFileHandler(
                log_file, maxBytes=1_000_000, backupCount=3, encoding='utf-8'
            )
            logger.info(f"Logging to system directory: {log_file}")
        except (PermissionError, OSError) as e:
            fallback_log_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            fallback_log_file.touch(mode=0o644, exist_ok=True)
            file_handler = RotatingFileHandler(
                fallback_log_file, maxBytes=1_000_000, backupCount=3, encoding='utf-8'
            )
            logger.warning(f"Using fallback log location: {fallback_log_file}")

        file_handler.setFormatter(formatter)
        handlers = [file_handler, console_handler]
    except Exception as e:
        handlers = [console_handler]
        logger.error(f"Failed to setup file logging: {str(e)}")

    # Очищаем существующие обработчики и добавляем новые
    logger.handlers.clear()
    for handler in handlers:
        logger.addHandler(handler)

    return logger

def get_config_value(section, key):
    return config.get(section, key).strip("'\"")

BASE_DIR = Path(__file__).parent
config = ConfigParser()
config.read('/etc/myapp/db.env')

UPLOAD_FOLDER = get_config_value('app', 'UPLOAD_FOLDER')
CREATED_FILES_FOLDER = get_config_value('app', 'CREATED_FILES_FOLDER')
ROOT_CERT_FOLDER = get_config_value('app', 'ROOT_CERT_FOLDER')
CERTSASN1 = get_config_value('app', 'CERTSASN1')
ROOT_CERT_TO_SEND = get_config_value('app', 'ROOT_CERT_TO_SEND')
PRIV_KEY_TO_SEND = get_config_value('app', 'PRIV_KEY_TO_SEND')
PWD_TO_SEND = get_config_value('app', 'PWD_TO_SEND')
APP_LOG_DIR = get_config_value('app', 'APP_LOG_DIR')
APP_LOG_FILE = get_config_value('app', 'APP_LOG_FILE')

FILENAME_SELF_SIGNED = get_config_value('app', 'FILENAME_SELF_SIGNED')
FILENAME_PRIVATE_KEY = get_config_value('app', 'FILENAME_PRIVATE_KEY')
FILENAME_CERTIFICATE_P10 = get_config_value('app', 'FILENAME_CERTIFICATE_P10')
FILENAME_CRL = get_config_value('app', 'FILENAME_CRL')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
logger = setup_logging()
db_manager = DatabaseManager(logger)


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
        beg_date = datetime.strptime(beg_date, '%Y-%m-%d').date() 
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

        if end_date <= beg_date:
                return render_template('error_self.html',
                    error="End date must be after start date"), 400

        certsAsn1 = app.config[CERTSASN1]
        prdn = ParamsRDN(surname= surname, givenName=given_name,
                            organizationalUnitName=org_unit_name, title=title,
                            commonName=common_name, organizationName=org_name,
                            countryName=org_country, stateOrProvinceName=org_region,
                            streetAddress=org_address, localityName=org_locality)
        
        selected_extensions = request.form.getlist('extensions')
        extensions_data = {}
        extentions = ExtentionsCert()
        for ext in selected_extensions:
            ext_params = {}
            
            if ext == 'basicConstraints':
                ext_params['max_depth'] = request.form.get('basicConstraints_max_depth', type=int)
                if ext_params['max_depth'] is None or ext_params['max_depth'] <= 0:
                    logger.error(f"Максимальная длина цепочки не должна быть целым числом большим 0!")
                    return render_template('error_self.html', error="Максимальная длина цепочки не должна быть целым числом большим 0!"), 500
                extentions.basicConstraints = True
                extentions.basicConstraints_subject_is_CA = True
                extentions.basicConstraints_max_depth_certs = ext_params['max_depth'] 
                logger.info(f"ENTENT :{ext_params['max_depth']}")
            # # Обработка keyUsage
            # elif ext == 'keyUsage':
            #     ext_params['mask'] = request.form.get('keyUsage_mask', type=int)
            #     if ext_params['mask'] is None:
            #         return "Некорректная битовая маска", 400
            
            # # Обработка extKeyUsage
            # elif ext == 'extKeyUsage':
            #     ext_params['types'] = request.form.getlist('extKeyUsage_types')
            #     if not ext_params['types']:
            #         return "Выберите хотя бы один тип использования", 400
            
            extensions_data[ext] = ext_params

        p = ParamsSelfSignedCert(alg_type=alg_type,
                                beg_validity_date=beg_date,
                                end_validity_date=end_date,
                                paramsRDN=prdn, extentions=extentions)

        serial_num = generate_serial_num()
        serial_num = db_manager.find_serial_number(serial_num)  # проверка на уникальность серийного номера

        cert_bytes, private_key, password = certsAsn1.create_selfsigned_cert(params=p, serial_num=serial_num)
        app.config[ROOT_CERT_TO_SEND] = cert_bytes
        app.config[PRIV_KEY_TO_SEND] = private_key
        app.config[PWD_TO_SEND] = password
        logger.info("Root self signed certificate was successfully created")
        return redirect(url_for('selfsigned_certificate_created'))

    except Exception as e:
        logger.error(f"Error while creating selfsigned certificate: {str(e)}")
        return render_template('error_self.html', error=str(e)), 500


@app.route('/certificate-created')
def selfsigned_certificate_created():
    certsAsn1 = app.config[CERTSASN1]
    if certsAsn1 is None:
        logger.error(f"app.config[CERTSASN1] is None")
        return redirect(url_for('create_certificate_page'))

    return render_template('selfsigned_certificate_created.html')  # TODO

@app.route('/download-certificate') 
def download_certificate():
    if app.config[ROOT_CERT_TO_SEND] is None:
        logger.error(f"app.config[ROOT_TO_SEND] is None")
        return "Self signed certificate not found (root_cert_bytes)", 404

    return send_file(
        BytesIO(app.config[ROOT_CERT_TO_SEND]),
        mimetype='application/x-x509-ca-cert', # указывает тип содержимого
        as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
        # download_name=f'certificate_{cert_data["serial_num"]}.der'
        download_name="root_certificate.der"
    )

@app.route('/download-private-key')
def download_private_key():
    if app.config[PRIV_KEY_TO_SEND] is None:
        logger.error(f"app.config[PRIV_KEY_TO_SEND] is None")
        return "Private key not found", 404

    key_file = BytesIO(app.config[PRIV_KEY_TO_SEND])
    return send_file(
        key_file,
        as_attachment=True,
        #download_name=f'private_key{cert_data["serial_num"]}.key',
        download_name="private.key",
        mimetype="application/octet-stream"  # Указывает, что это бинарный файл
    )

@app.route('/show-password')
def show_password():
    if app.config[PWD_TO_SEND] is None:
        logger.error(f"Password not found")
        return "Password not found", 404

    return render_template('show_password.html', password=app.config[PWD_TO_SEND])


'''------------------------ ОБНОВЛЕНИЕ КОРНЕВОГО СЕРТИФИКАТА -------------------------------'''
@app.route('/update-rootcert-page')
def update_rootcert_form():
    return render_template('update_rootcert.html')

@app.route('/api/update_rootcert', methods=['POST'])
def update_rootcert():
    try:
        if 'certfile' not in request.files:
            logger.error(f"No certificate file (.der) was sent to server")
            return render_template('error_update_rootcert.html', error="No certificate file (.der) was sent to server"), 400

        filecert = request.files['certfile']
        if filecert.filename == '':
            logger.error(f"Empty filename for certificate file")
            return render_template('error_update_rootcert.html', error="Empty filename for certificate file"), 400

        if 'privatekey' not in request.files:
            logger.error(f"No private.key was sent to server")
            return render_template('error_update_rootcert.html', error="No private.key was sent to server"), 400

        filekey = request.files['privatekey']
        if filekey.filename == '':
            logger.error(f"Empty filename for private key file")
            return render_template('error_update_rootcert.html', error="Empty filename for private key file"), 400

        req_data = request.form
        password = req_data.get('password', '').strip()
        if not password:
            logger.error(f"Password must not be empty")
            return render_template('error_update_rootcert.html', error="Password must not be empty"), 400


        # СОХРАНЕНИЕ ФАЙЛОВ ДЛЯ ДЕМОНА
        save_dir = '/root_cert_daemon'
        os.makedirs(save_dir, exist_ok=True)

        cert_filename = secure_filename('root_certificate.der')
        cert_path = os.path.join(save_dir, cert_filename)
        filecert.seek(0)  
        filecert.save(cert_path)

        key_filename = secure_filename('private.key')
        key_path = os.path.join(save_dir, key_filename)
        filekey.seek(0)  
        filekey.save(key_path)

        password_file = os.path.join(save_dir, 'password.txt')
        with open(password_file, 'w') as f:
            f.write(password)
        ############################

        #получаем как строку байт
        cert_bytes = filecert.read()
        if not cert_bytes:
            logger.error(f"Certificate file is empty")
            return render_template('error_update_rootcert.html',
                                error="Certificate file is empty"), 400
        private_key = filekey.read()
        if not private_key:
            logger.error(f"Private key file is empty")
            return render_template('error_update_rootcert.html',
                                error="Private key file is empty"), 400

        certsAsn1 = app.config[CERTSASN1]
        certsAsn1.change_active_root_cert(cert_bytes=cert_bytes,
                                        private_key=private_key,
                                        password=password)

        return render_template('success.html',
                            message="Активный корневой сертификат успешно изменен")

    except Exception as e:
        logger.error(f"Error updating root certificate: {str(e)}")
        return render_template('error_update_rootcert.html', error=str(e)), 500

'''------------------------------------------------ ОТЗЫВ СЕРТИФИКАТОВ ------------------------------------'''
@app.route('/revoke-certificate')
def revoke_certificate_page():
    try:
        revoked_certs = []
        with db_manager.get_cursor() as cursor:
            # cursor.execute("SELECT serial_number, is_revoked, revoke_date, invalidity_date, revoke_reason, source_serial_number FROM certificates")
            cursor.execute("SELECT serial_number, is_revoked, revoke_date, invalidity_date, revoke_reason, source_serial_number, send_to_ca FROM certificates")
            certificates = cursor.fetchall()

            for cert in certificates:
                revoked_certs.append({
                    'serial_number': cert[0],  # serial_number
                    'status': "Отозван" if cert[1] else "Не отозван",  # is_revoked
                    'revoke_date': cert[2].strftime('%Y-%m-%d') if cert[2] else None,  # revoke_date
                    'invalidity_date': cert[3].strftime('%Y-%m-%d') if cert[2] else None,  # invalidity_date (исправлена проверка на revoke_date)
                    'revoke_reason': cert[4],  # revoke_reason
                    'source_serial_number': cert[5],  # source_serial_number


                    'send_to_ca': "Отправлен" if cert[6] else "Не отправлен"  
                })

        return render_template('revoke_certificate.html', certificates=revoked_certs)

    except Exception as e:
        return render_template('error.html', error=str(e)), 500

@app.route('/api/revoke-certificate', methods=['POST'])
def revoke_certificate():
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
@app.route('/send-p10')
def upload_p10_form():
    return render_template('send_p10.html')


@app.route('/api/create_certificate_p10', methods=['POST'])
def create_certificate_p10():
    try:
        if 'file' not in request.files:
            return render_template('error_p10.html', error="No file was sent to server"), 400

        file = request.files['file']
        if file.filename == '':
            return render_template('error_p10.html', error="Empty filename"), 400

        template = request.form.get('template')
        # if not template:
        #     return render_template('error_p10.html', error="No template was selected"), 400

        beg_date_str = request.form.get('beg_validity_date')
        end_date_str = request.form.get('end_validity_date')

        if not beg_date_str or not end_date_str:
            return render_template('error_p10.html',
                                error="Please specify both start and end validity dates"), 400

        try:
            beg_validity_date = datetime.strptime(beg_date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            end_validity_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)

            if end_validity_date <= beg_validity_date:
                return render_template('error_p10.html',
                                    error="End date must be after start date"), 400

        except ValueError as e:
            return render_template('error_p10.html',
                                error=f"Invalid date format: {str(e)}"), 400


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
        if template:
            template_file = f"./cert_templates/{template}.txt"
            if not os.path.exists(template_file):
                error_msg = f"Certificate template file '{template}' not found"
                logger.error(error_msg)
                return render_template('error_p10.html', error=error_msg), 404

            temp_dir = file_to_dict(template_file)

            value_0 = [key for key, value in temp_dir.items() if value == '0']
            for values in value_0:
                setattr(rdn_template, values, False)
            value_1 = [key for key, value in temp_dir.items() if value == '1']
            for values in value_1:
                setattr(rdn_template, values, True)

        cert_template = CertTemplate(rdn_template)  # пока не трогаем

        serial_num = db_manager.find_serial_number(generate_serial_num())

        try:
            cert_bytes = certsAsn1.create_cert(serial_num=serial_num,
                                       beg_validity_date=beg_validity_date,
                                       end_validity_date=end_validity_date,
                                       cert_template=cert_template,
                                       pem_csr=pem_csr)
        except ErrNoRootCert as e:
            return render_template('error_p10.html',
                            error=f"{str(e)}"), 400
        except ErrParamsTemplate as e:
            return render_template('error_p10.html',
                            error=f"{str(e)}"), 400

        if CERTSASN1 not in app.config:
            raise Exception("Configuration 'CERTASN1' not found in app.config")

        if certsAsn1.rootCert is None:
            raise Exception("Root self signed certificate not found")
        source_num = certsAsn1.rootCert.serial_num

        rc = db_manager.insert_to_db(serial_num, source_num)
        if not rc:
            raise Exception("Inserting certificate into database failed")
        res_filename =  f"./{CREATED_FILES_FOLDER}/res.pem"
        with open(res_filename, 'w') as f:
            f.write(bytes_to_pem(cert_bytes, pem_type="CERTIFICATE")) # !!! pem_type - НЕ МЕНЯТЬ
        # with open(res_filename, 'wb') as f:
        #     f.write(cert_bytes)

        logger.info("Certificate was successfully created")

        return redirect(url_for('certificate_created_p10'))

    except Exception as e:
        logger.error(f"Error while creating certificate: {str(e)}")
        return render_template('error_p10.html',
                            error=f"Error while creating certificate: {str(e)}"), 500

@app.route('/certificate-created-request')
def certificate_created_p10():
    res_filename = os.path.join(CREATED_FILES_FOLDER, "res.der")

    if not os.path.exists(res_filename):
        return redirect(url_for('upload_p10_form'))

    try:
        return render_template('new_certificate_created.html')

    except Exception as e:
        logger.error(f"Error in certificate_created_p10: {str(e)}")
        return redirect(url_for('upload_p10_form'))

@app.route('/download-certificate-p10')
def download_certificate_p10():
    res_filename = os.path.join(CREATED_FILES_FOLDER, "res.pem")

    # Проверяем существование файла
    if not os.path.exists(res_filename):
        return redirect(url_for('upload_p10_form'))

    try:
        # Отправляем файл для скачивания
        # return send_file(
        #     res_filename,  # Путь к файлу
        #     mimetype='application/x-pem-file',  # MIME-тип для PEM-файлов
        #     as_attachment=True,  # Принудительное скачивание
        #     download_name='certificate.pem'  # Имя файла при скачивании
        # )

        return send_file(
            res_filename,  # Путь к файлу (PEM внутри)
            mimetype='application/x-x509-ca-cert',  
            as_attachment=True, 
            download_name='certificate.cer'  
        )

        # return send_file(
        #     res_filename,
        #     mimetype='application/x-x509-ca-cert', # указывает тип содержимого
        #     as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
        #     # download_name=f'certificate_{cert_data["serial_num"]}.der'
        #     download_name="certificate.der"
        # )

    except Exception as e:
        logger.error(f"Error downloading certificate: {str(e)}")
        return redirect(url_for('upload_p10_form'))


'''------------------------CRL КНОПО4КА ------------'''
@app.route('/download-crl')
def download_crl():
    logger.info("start download_crl():")

    try:
        certsAsn1 = app.config[CERTSASN1]

        array_of_revoked_certificate = db_manager.get_revoked_certificates()
        logger.info(f"array_of_revoked_certificate: {array_of_revoked_certificate}")
        crl_bytes = certsAsn1.create_crl(
                        revokedCerts=array_of_revoked_certificate,
                        thisUpdate=datetime.now(tz=timezone.utc),
                        nextUpdate=datetime.now(tz=timezone.utc) + timedelta(days=10))
        logger.info("crl created")
        res_filename = os.path.join(CREATED_FILES_FOLDER, "crl.der")
        logger.info(f"saving to: {res_filename}")
        with open(res_filename, 'w') as f:
            f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL"))

        return send_file(
            res_filename,
            mimetype='application/x-x509-ca-cert', # указывает тип содержимого
            as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
            # download_name=f'certificate_{cert_data["serial_num"]}.der'
            download_name="crl.der"
        )

    except Exception as e:
        logger.error(f"Error create crl: {str(e)}")

        # return redirect(url_for('index'))
        return render_template('error.html',
                            error=f"Error create crl: {str(e)}"), 500

'''-------------------------------------------------------------------------------'''
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

        # init_root_cert()
        app.config[CERTSASN1] = CertsAsn1()
        app.config[ROOT_CERT_TO_SEND] = None
        app.config[PRIV_KEY_TO_SEND] = None
        app.config[PWD_TO_SEND] = None

        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        sys.exit(1)


initialize_application()

if __name__ == '__main__':
    # Локальный запуск (только для запуска через python3
    app.run(host='0.0.0.0', port=5000, debug=True)

