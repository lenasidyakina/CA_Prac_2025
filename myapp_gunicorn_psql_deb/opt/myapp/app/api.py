from wsgi import appl, CERTSASN1, LOGGER, STORAGE
from app import insert_to_db, ROOT_CERT_PATH, UPLOAD_FOLDER
from datetime import datetime, timezone,  timedelta
from asn1_parser.models.AlgParams import AlgTypes
from asn1_parser.models.paramsSelfSignedCert import ParamsSelfSignedCert, ParamsRDN
from asn1_parser.asn1_parse import bytes_to_pem, generate_serial_num
from asn1_parser.models.CertTemplate import CertTemplate, RDNTemplate

from flask import request, jsonify, send_file, render_template, redirect, url_for
from io import BytesIO
from psycopg2.extras import DictCursor
from logging import Logger
import os
from werkzeug.utils import secure_filename


# главная страница
@appl.route('/')
def index():
    return render_template('index.html')

'''------------------------------------------------ СОЗДАНИЕ САМОПОДПИСНОГО СЕРТИФИКАТА -------------------------------------'''
@appl.route('/create-selfsigned-certificate')
def create_certificate_page():
    logger = appl.config[LOGGER]
    logger.info("create_certificate_page")
    return render_template('create_selfsigned_certificate.html')

@appl.route('/api/create-selfsigned-certificate', methods=['POST'])
def create_selfsigned_certificate():
    try:
        logger = appl.config[LOGGER]
        logger.info("create_selfsigned_certificate")
        logger.warning("here create_selfsigned_certificate -----")
        storage = appl.config[STORAGE]

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

        certsAsn1 = appl.config[CERTSASN1]
        logger.warning(f"RootCert = {certsAsn1.rootCert}")
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
        serial_num = storage.find_serial_number(serial_num)  # проверка на уникальность серийного номера
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
        
        appl.config['CERT_DATA'] = {
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
    
@appl.route('/certificate-created')
def selfsigned_certificate_created():
    logger = appl.config[LOGGER]
    logger.info("selfsigned_certificate_created")
    cert_data = appl.config.get('CERT_DATA', {})
    if not cert_data:
        return redirect(url_for('create_certificate_page'))
    
    return render_template('selfsigned_certificate_created.html',
                         serial_num=cert_data['serial_num'])

@appl.route('/download-certificate')
def download_certificate():
    logger = appl.config[LOGGER]
    logger.info("download_certificate")
    cert_data = appl.config.get('CERT_DATA')
    if not cert_data or 'cert_bytes' not in cert_data:
        return "Self signed certificate not found", 404
    
    return send_file(
        BytesIO(cert_data['cert_bytes']),
        mimetype='application/x-x509-ca-cert', # указывает тип содержимого
        as_attachment=True,  # указание браузеру, что файл должен быть скачан (а не открыт в браузере)
        # download_name=f'certificate_{cert_data["serial_num"]}.der'
        download_name="certificate.der"
    )

@appl.route('/download-private-key')
def download_private_key():
    logger = appl.config[LOGGER]
    logger.info("download_private_key")
    cert_data = appl.config.get('CERT_DATA')
    if not cert_data or 'private_key' not in cert_data:
        return "Private key not found", 404
    
    key_file = BytesIO(cert_data['private_key']) 
    return send_file(
        key_file,
        as_attachment=True,    
        #download_name=f'private_key{cert_data["serial_num"]}.key',
        download_name="private.key",
        mimetype="application/octet-stream"  # Указывает, что это бинарный файл
    )

    # return send_file(
    #     BytesIO(cert_data['private_key']),
    #     mimetype='application/x-pem-file',
    #     as_attachment=True,
    #     download_name=f'private_key_{cert_data["serial_num"]}.pem'
    # )

@appl.route('/show-password')
def show_password():
    logger = appl.config[LOGGER]
    logger.info("show_password")
    cert_data = appl.config.get('CERT_DATA')
    if not cert_data or 'password' not in cert_data:
        return "Password not found", 404
    
    return render_template('show_password.html', password=cert_data['password'])

'''------------------------------------------------ ОТЗЫВ СЕРТИФИКАТОВ ------------------------------------'''
@appl.route('/revoke-certificate')
def revoke_certificate_page():
    try:
        logger = appl.config[LOGGER]
        logger.info("revoke_certificate_page")
        stogare = appl.config[STORAGE]
        conn = stogare.get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        cursor.execute("SELECT * FROM certificates")
        certificates = cursor.fetchall()
        
        cursor.close()

        certs_data = []
        for cert in certificates:
            certs_data.append({
                'serial_number': cert['serial_number'],
                'status': "Отозван" if cert['is_revoked'] else "Не отозван",
                'revoke_date': cert['revoke_date'].strftime('%Y-%m-%d') if cert['revoke_date'] else None,
                'invalidity_date': cert['invalidity_date'].strftime('%Y-%m-%d') if cert['revoke_date'] else None,
                'revoke_reason': cert['revoke_reason'],
                'source_serial_number': cert['source_serial_number']
                #'send_to_ocsp': "Да" if cert['send_to_ocsp'] else "Нет"
            })
        
        return render_template('revoke_certificate.html', certificates=certs_data)
    
    except Exception as e:
        return render_template('error.html', error=str(e)), 500


@appl.route('/api/revoke-certificate', methods=['POST'])
def revoke_certificate():
    try:
        logger = appl.config[LOGGER]
        logger.info("revoke_certificate")
        stogare = appl.config[STORAGE]

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
        
        conn = stogare.get_db_connection()
        cursor = conn.cursor()
        try:
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
            
            conn.commit()
            return jsonify({
                "status": "success",
                "message": f"Успешно отозвано {len(certs_to_revoke)} сертификатов"
            })
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": f"Ошибка базы данных: {str(e)}"}), 500
        finally:
            cursor.close()
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
'''------------------------------------------------ СОЗДАНИЕ СЕРТИФИКАТА ПО ЗАПРОСУ -------------------------------------'''
# прием запроса на создание сертификата (файла .p10)
@appl.route('/api/create_certificate_p10', methods=['POST'])
def create_certificate_p10(logger: Logger):
    logger = appl.config[LOGGER]
    logger.info("create_certificate_p10")
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

        certsAsn1 = appl.config[CERTSASN1]
        
        rdn_template = RDNTemplate()    
        # TODO заполнить поля rdn_template на основе файла-шаблона от пользователя (если файл не поступил, то поля не трогаем)
        rdn_template.surname = rdn_template.givenName = rdn_template.streetAddress = False  
        cert_template = CertTemplate(rdn_template)  # пока не трогаем

        # TODO интерфейс для отправки запроса p10
        storage = appl.config[STORAGE]
        serial_num = storage.find_serial_number(generate_serial_num())
        beg_validity_date = datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc)  # TODO interface
        end_validity_date = datetime(2025, 6, 7, 0, 0, 0, tzinfo=timezone.utc)  # TODO interface
        cert_bytes = certsAsn1.create_cert(serial_num=serial_num, 
                                       beg_validity_date=beg_validity_date,
                                       end_validity_date=end_validity_date,
                                       cert_template=cert_template, 
                                       pem_csr=pem_csr)
        
        rc = insert_to_db(serial_num, appl.config['CERT_DATA']['serial_num']) # TODO проверка на то, что  appl.config['CERT_DATA']['serial_num'] не none
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
    except Exception as e:
        logger.error(f"{str(e)}")
        return jsonify({"error": f"Failed to send PEM: {str(e)}"}), 500 