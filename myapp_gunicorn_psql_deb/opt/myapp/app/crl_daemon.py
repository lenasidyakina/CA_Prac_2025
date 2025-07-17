#!/usr/bin/env python3
import time
import os
import logging
import signal
import sys
from pathlib import Path

# Теперь можно импортировать напрямую
from asn1_parser.asn1_parse import bytes_to_pem
from datetime import datetime, timezone, timedelta
from asn1_parser.models.RootCert import restore_root_cert
from asn1_parser.cert_parse import CertsAsn1
from db.DatabaseManager import DatabaseManager

CONFIG_FILE = '../../../etc/myapp/crl_daemon.conf'


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
                logging.FileHandler(self.log_file),
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

        self.db_manager = DatabaseManager(logger=self.logger)
        self.logger.info(f"inited db_manager")

        self.certAsn1 = CertsAsn1()
        self.logger.info(f"inited CertsAsn1 + Bicry")
        try:
            with open('./root_cert_daemon/root_certificate.der', 'rn') as f:
                cert_bytes = f.read()
            self.logger.info(f"read root_cert_daemon/cert_bytes")
            with open('./root_cert_daemon/private.key', 'rn') as f:
                private_key = f.read()
            self.logger.info(f"read root_cert_daemon/private.key")
            with open('./root_cert_daemon/pwd.txt', 'r') as f:
                password = f.read()
            self.logger.info(f"read root_cert_daemon/pwd.txt")
            self.certsAsn1.change_active_root_cert(cert_bytes=cert_bytes,
                                                    private_key=private_key,
                                                    password=password)
            self.logger.info(f"change_active_root_cert end")
        except Exception as e:
            self.logger.error(f"ERROR: read files root_cert or change_active_root_cert")

    def _read_interval_from_config(self):
        """Чтение интервала из конфигурационного файла"""
        config_file = CONFIG_FILE
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
                array_of_revoked_certificate = self.db_manager.get_revoked_certificates()
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                crl_bytes = self.certsAsn1.create_crl(
                    revokedCerts=array_of_revoked_certificate,
                    thisUpdate=datetime.now(tz=timezone.utc),
                    nextUpdate=datetime.now(tz=timezone.utc) + timedelta(seconds=self.interval))
                
                with open('/opt/myapp/app/crl.pem', 'w') as f:
                    f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL"))    
                self.logger.info(f"Updated numbers at {current_time}")

            except Exception as e:
                self.logger.error(f"Error: {str(e)}", exc_info=True)

            # Ожидаем указанный интервал
            time.sleep(self.interval)

    def stop(self):
        self._running = False
        self.certsAsn1.bicrypt.close()
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
