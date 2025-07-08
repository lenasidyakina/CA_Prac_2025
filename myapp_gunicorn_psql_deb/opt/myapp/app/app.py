from flask import Flask, request, jsonify, send_file, render_template
import os
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from configparser import ConfigParser
import logging
from paramsSelfSignedCert import ParamsSelfSignedCert
from asn1_parse import bytes_to_pem, create_cert
import asn1
from pyasn1_modules import rfc5280
    

def create_rdn(params: ParamsSelfSignedCert) -> bytes:
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)    # rdnSequence
    for p in params.get_list():
        encoder.enter(asn1.Numbers.Set)         # RelativeDistinguishedName
        encoder.enter(asn1.Numbers.Sequence)    # AttributeTypeAndValue
        encoder.write(p[1], asn1.Numbers.ObjectIdentifier)
        encoder.write(p[0], asn1.Numbers.UTF8String)
        encoder.leave()                         # out AttributeTypeAndValue
        encoder.leave()                         # out RelativeDistinguishedName
    encoder.leave()                         # out rdnSequence
    rdn_bytes = encoder.output()
    return rdn_bytes


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_config():
    #Получение конфигурации БД из файла
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
        logger.error(f"Error reading DB config: {str(e)}")
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
        logger.info("Successfully connected to PostgreSQL")
        return conn
    except psycopg2.Error as e:
        logger.error(f"PostgreSQL connection error: {str(e)}")
        raise

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads' #дир-рия для хранения загруженных файлов (полученных из запроса файлов)
CREATED_FILES_FOLDER = 'created_files'
ALLOWED_EXTENSIONS = {'p10'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# проверка расширения файла
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# главная страница
@app.route('/')
def index():
    return render_template('index.html')

# страница создания самоподписного сертификата 
@app.route('/create-certificate')
def create_certificate_page():
    return render_template('create_certificate.html')

# метод для создания самоподписного сертификата
@app.route('/api/create-certificate', methods=['POST'])
def create_certificate():
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
        name = req_data.get('name', '').strip()
        department = req_data.get('department', '').strip()
        position = req_data.get('position', '').strip()
        
        # дополнительные поля
        snils = req_data.get('snils', '').strip()
        email = req_data.get('email', '').strip()

        
        p = ParamsSelfSignedCert("Tsurname", "TgivenName", "TorganizationalUnitName", "Ttitle",
                 "TcommonName", "TorganizationName",
                 "TcountryName", "TstateOrProvinceName", "TstreetAddress", "TlocalityName")
        print(p)
        # отладная печать
        # print(f"""
        # Данные формы:
        # - Общее имя: {cert.commonName}
        # - Организация: {cert.organizationName}
        # - Юридический адрес: {cert.countryName}, {cert.stateOrProvinceName}, {cert.localityName}, {cert.streetAddress}
        # - Сотрудник: {cert.surname} {cert.givenName}
        # - Подразделение: {cert.organizationalUnitName}
        # - Должность: {cert.title}
        # """)

        logger.info("Создание самоподписного сертификата")

        # Здесь должна быть логика создания сертификата
        # и сохранения в БД

        return jsonify({
            "status": "success",
            "message": "Data was successfully accepted"
        })

    except Exception as e:
        logger.error(f"Error in create_certificate: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

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
    cursor.execute("SELECT * FROM certificates WHERE is_revoked = TRUE")
    revoked_certificates = cursor.fetchall()
    conn.close()
    print(revoked_certificates)
    return revoked_certificates

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
        # создание папки, если ее нет
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
        
        # сохранение полученного файл
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        ''' new '''
        with open(file_path, 'r') as pem_file:
            pem_csr = pem_file.read()
        cert_bytes = create_cert(pem_csr)
        # with open('res.der', 'wb') as f:
        #     f.write(cert_bytes)
        res_filename='./created_files/res.pem'
        with open(res_filename, 'w') as f:
            f.write(bytes_to_pem(cert_bytes, "CERTIFICATE"))

        return send_file(
        res_filename,
        as_attachment=True,
        download_name='certificate.pem', 
        mimetype='application/x-pem-file'
    )
    
    except Exception as e:
        return jsonify({"error": f"Failed to send PEM: {str(e)}"}), 500 
    
    '''old'''
    # return jsonify({
    #         "status": "success",
    #         "message": "File uploaded successfully",
    #         "filename": filename
    #     })
    
    # except Exception as e:
    #     return jsonify({"error": f"Upload failed: {str(e)}"}), 500


# # отправка .pem файла (ЧИСТО ЭКСПЕРИМЕНТ ОТПРАВКИ ФАЙЛА ;) )
# @app.route('/api/get_pem/<filename>', methods=['GET'])
# def get_pem(filename):
#     try:
#         # проверка существования файла
#         base_name = os.path.splitext(filename)[0]  # убираем расширение .p10
#         pem_file = f"{base_name}.pem"
#         pem_path = os.path.join(UPLOAD_FOLDER, pem_file)
        
#         if not os.path.exists(pem_path):
#             return jsonify({"error": ".pem file not found"}), 404
        
#         return send_file(
#             pem_path,
#             as_attachment=True,
#             download_name=pem_file,
#             mimetype='application/x-pem-file'
#         )
    
#     except Exception as e:
#         return jsonify({"error": f"Failed to send PEM: {str(e)}"}), 500

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('created_files', exist_ok=True)
    required_templates = ['index.html', 'revoke_certificate.html', 'create_certificate.html']
    for template in required_templates:
        if not os.path.exists(f'./templates/{template}'):
            logger.error(f"Template {template} not found in templates directory")
    # try:
    #     conn = get_db_connection()
    #     conn.close()
    #     logger.info("Database connection test successful")
    # except Exception as e:
    #     logger.error(f"Database connection test failed: {str(e)}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)