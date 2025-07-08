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
                # для тестирования
                for _ in range(3):
                    serial_num = generate_serial_num()
                    r = RevokedCertificates(serialNumber=serial_num,
                                            revocationDate=datetime(2025, 7, 10, tzinfo=timezone.utc))
                    array_of_revoked_certificate.append(r)

                # TODO Данные из корневого сертификата (их получение будет добавлено потом)
                p = ParamsSelfSignedCert("", "", "", "", "", "", "TcountryName", "", "", "")

                crl_bytes = create_crl(
                    revokedCerts=array_of_revoked_certificate,
                    issuer=p,
                    thisUpdate=datetime.now(tz=timezone.utc),
                    nextUpdate=datetime.now(tz=timezone.utc) + timedelta(seconds=self.interval))

                with open('res.pem', 'w') as f:
                    f.write(bytes_to_pem(crl_bytes, pem_type="X509 CRL"))  # !!! pem_type - НЕ МЕНЯТЬ

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