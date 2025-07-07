from flask import Flask, request, jsonify, send_file, render_template
import os
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from configparser import ConfigParser


def get_db_config():
    config = ConfigParser()
    config.read('/etc/myapp/db.env')
    return {
        'host': config.get('postgresql', 'DB_HOST'),
        'port': config.get('postgresql', 'DB_PORT'),
        'database': config.get('postgresql', 'DB_NAME'),
        'user': config.get('postgresql', 'DB_USER'),
        'password': config.get('postgresql', 'DB_PASS')
    }

#  получение соединения с БД
def get_db_connection():
    config = get_db_config()
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            dbname=config['database'],
            user=config['user'],
            password=config['password']
        )
        return conn
    except Exception as e:
        print(f"Ошибка подключения к PostgreSQL: {str(e)}")
        raise


app = Flask(__name__)

UPLOAD_FOLDER = 'uploads' #дир-рия для хранения загруженных файлов (полученных из запроса файлов)
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

        # отладная печать
        print(f"""
        Данные формы:
        - Общее имя: {common_name}
        - Организация: {org_name}
        - Юридический адрес: {org_country}, {org_region}, {org_locality}, {org_address}
        - Сотрудник: {surname} {name}
        - Подразделение: {department}
        - Должность: {position}
        - СНИЛС: {snils}
        - Email: {email}
        """)

        # здесь будет логика создания сертификата


        return jsonify({
            "status": "success",
            "message": "Data was successfully accepted"
        })
    

    except Exception as e:
        return jsonify({
            "error": "Внутренняя ошибка сервера",
            "details": str(e)
        }), 500

@app.route('/revoke-certificate')
def revoke_certificate_page():
    return render_template('revoke_certificate.html')

# получить сертификаты из БД и отметить некоторые из них как отозванные
@app.route('/api/revoke-certificate', methods=['POST'])
def revoke_certificate():
    try:
        cert_file = request.files.get('certificate')
        if not cert_file:
            return jsonify({"error": "Файл сертификата не предоставлен"}), 400
            
        filename = secure_filename(cert_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        cert_file.save(filepath)
        
        # Здесь должна быть логика отзыва сертификата
        # В реальной системе это работа с CA (Certificate Authority)
        
        return jsonify({
            "status": "success",
            "message": f"Сертификат {filename} отозван",
            "revoked_cert": filepath
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        
        return jsonify({
            "status": "success",
            "message": "File uploaded successfully",
            "filename": filename
        })
    
    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500

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
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(host='0.0.0.0', port=5000)