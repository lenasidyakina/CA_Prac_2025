from config import get_db_config
from asn1_parser.asn1_parse import generate_serial_num

import psycopg2
from logging import Logger


class Storage:
    def __init__(self, logger: Logger):
        config = get_db_config(logger=logger)
        try:
            conn = psycopg2.connect(
                host=config['host'],
                port=config['port'],
                dbname=config['database'],
                user=config['user'],
                password=config['password'],
                # connect_timeout=10  # Таймаут подключения 10 секунд
            )
            # logger.info("Successfully connected to data base")
            self.connection = conn
        except psycopg2.Error as e:
            errtext = f"Data base connection error: {str(e)}"
            logger.error(errtext)
            raise Exception(errtext)

    def get_db_connection(self):
        return self.connection
    
    def find_serial_number(self, number):
        cursor = self.connection.cursor()
        number_str = str(number)
        while True:
            cursor.execute(
                "SELECT 1 FROM certificates WHERE serial_number = %s",
                (number_str,)
            )
            
            if not cursor.fetchone():
                return number
            
            number = generate_serial_num()
            number_str = str(number)
        
        return number