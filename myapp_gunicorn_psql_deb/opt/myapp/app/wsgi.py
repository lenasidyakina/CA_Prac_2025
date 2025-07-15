from app import setup_logging, UPLOAD_FOLDER, create_app_folders, get_revoked_certificates
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