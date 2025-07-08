#!/usr/bin/env python3
import time
import os
from datetime import datetime
import logging
import signal
import sys


class NumberLogger:
    def __init__(self):
        self.log_dir = '/var/log/myapp/'
        os.makedirs(self.log_dir, exist_ok=True)

        self.log_file = os.path.join(self.log_dir, 'numbers.log')
        self.error_file = os.path.join(self.log_dir, 'numbers.error.log')

        self.interval = 15  # Интервал в секундах
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
        except Exception as e:
            self.logger.error(f"Failed to initialize log file: {str(e)}")

    def get_array(self):
        """
        Внешняя функция для получения массива чисел.
        Здесь можно реализовать получение данных из БД, API и т.д.
        """
        # Пример: возвращаем случайные числа
        import random
        return [random.randint(1, 100) for _ in range(5)]

    def run(self):
        self._running = True
        self.logger.info("Number logger started")

        while self._running:
            try:
                # Получаем новый массив
                numbers = self.get_array()
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Записываем в файл
                with open(self.log_file, 'w') as f:
                    f.write(f"Last update at {current_time}\n")
                    for number in numbers:
                        f.write(f"{number}\n")
                    f.flush()

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