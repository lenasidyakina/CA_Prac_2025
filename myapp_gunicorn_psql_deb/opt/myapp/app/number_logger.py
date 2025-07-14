#!/usr/bin/env python3
import time
import os
import logging
import signal
import sys
from app import get_revoked_certificates
from datetime import datetime, timezone, timedelta
from paramsSelfSignedCert import ParamsSelfSignedCert
from asn1_parse import bytes_to_pem, create_crl, generate_serial_num
from RevokedCertificates import RevokedCertificates
from models.RootCert import restore_root_cert
from cert_parse import CertsAsn1


ROOT_CERT_FOLDER = 'root_certs'  # для корневых сертификатов
ROOT_CERT_PATH = os.path.join(ROOT_CERT_FOLDER, 'root_cert.der')


class NumberLogger:
    def __init__(self):
        self.log_dir = '/var/log/myapp/'
        os.makedirs(self.log_dir, exist_ok=True)

        self.log_file = os.path.join(self.log_dir, 'numbers.log')
        self.error_file = os.path.join(self.log_dir, 'numbers.error.log')

        # Чтение интервала из конфига
        self.interval = self._read_interval_from_config()

        self._running = False

        # Настройка логирования
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.error_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('NumberLogger')

        # Инициализация файла
        try:
            with open(self.log_file, 'w') as f:
                f.write(f"Log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

            os.chmod(self.log_file, 0o644)
            os.chmod(self.error_file, 0o644)
        except Exception as e:
            self.logger.error(f"Failed to initialize log file: {str(e)}")

    def _read_interval_from_config(self):
        """Чтение интервала из конфигурационного файла"""
        config_file = 'app_config.conf'
        default_interval = 15  # Значение по умолчанию

        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if line.startswith('TIME='):
                            try:
                                return int(line.split('=')[1].strip())
                            except (ValueError, IndexError):
                                self.logger.warning(f"Invalid TIME value in config, using default {default_interval}")
                                return default_interval
            return default_interval
        except Exception as e:
            self.logger.error(f"Error reading config file: {str(e)}, using default interval")
            return default_interval


    def run(self):
        self._running = True
        self.logger.info(f"Number logger started with interval {self.interval} seconds")

        while self._running:
            try:
                array_of_revoked_certificate = get_revoked_certificates()
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
                with open(ROOT_CERT_PATH, 'rb') as f:  
                    cert_bytes = f.read()
                root = restore_root_cert(cert_bytes)
                print(root)
                certsAsn1 = CertsAsn1(rootCert=root)

                
                crl_bytes = certsAsn1.create_crl(
                    revokedCerts=array_of_revoked_certificate, 
                    thisUpdate=datetime.now(tz=timezone.utc),
                    nextUpdate=datetime(2027, 7, 10, tzinfo=timezone.utc))

                
                with open('/opt/myapp/app/crl.pem', 'w') as f:
                    f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL")) # !!! pem_type - НЕ МЕНЯТЬ
            
                
                self.logger.info(f"Updated numbers at {current_time}")

            except Exception as e:
                self.logger.error(f"Error: {str(e)}", exc_info=True)

            # Ожидаем указанный интервал
            time.sleep(self.interval)

    def stop(self):
        self._running = False
        self.logger.info("Number logger stopped")


def main():
    logger = NumberLogger()

    # Обработка сигналов
    def handle_signal(signum, frame):
        logger.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.run()


if __name__ == "__main__":
    main()
