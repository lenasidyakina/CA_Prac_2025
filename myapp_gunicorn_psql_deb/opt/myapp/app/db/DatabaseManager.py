import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from configparser import ConfigParser
from contextlib import contextmanager
from asn1_parser.asn1_parse import generate_serial_num
from asn1_parser.models.RevokedCertificates import RevokedCertificates, CRLReasonCode


class DatabaseManager:
    def __init__(self, logger):
        """Инициализация менеджера базы данных с логгером"""
        self._connection = None
        self.logger = logger
        self._connect()
        
    def _connect(self):
        """Устанавливает соединение с базой данных"""
        config = self._get_db_config()
        try:
            self._connection = psycopg2.connect(
                host=config['host'],
                port=config['port'],
                dbname=config['database'],
                user=config['user'],
                password=config['password'],
                connect_timeout=10
            )
            self.logger.info("Successfully connected to database")
        except psycopg2.Error as e:
            self.logger.error(f"Database connection error: {str(e)}")
            raise
            
    def _get_db_config(self):
        """Получает конфигурацию базы данных"""
        config = ConfigParser()
        try:
            config.read('../../../etc/myapp/db.env')
            print(config)
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
            self.logger.error(f"Error reading database configuration file: {str(e)}")
            raise
    
    @contextmanager
    def get_cursor(self):
        """Предоставляет курсор для работы с базой данных"""
        cursor = None
        try:
            if self._connection.closed:
                self._connect()
                
            cursor = self._connection.cursor()
            yield cursor
            self._connection.commit()
        except Exception as e:
            if self._connection:
                self._connection.rollback()
            self.logger.error(f"Database error: {str(e)}")
            raise
        finally:
            if cursor:
                cursor.close()
    
    def find_serial_number(self, number):
        with self.get_cursor() as cursor:
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

    def get_revoked_certificates(self):
        revoked_certificates = []
        with self.get_cursor() as cursor:
            cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE")
            
            for row in cursor.fetchall():
                serialNumber = int(row[0])
                revocationDate = row[1]
                crlReasonCode = CRLReasonCode[row[2]] if row[2] else CRLReasonCode.unspecified
                invalidityDate = row[3]
                
                revoked_certificates.append(
                    RevokedCertificates(
                        serialNumber=serialNumber,
                        revocationDate=revocationDate,
                        crlReasonCode=crlReasonCode,
                        invalidityDate=invalidityDate
                    )
                )
        return revoked_certificates

    

    def close(self):
        """Закрывает соединение с базой данных"""
        if self._connection and not self._connection.closed:
            self._connection.close()
            self.logger.info("Database connection closed")
    
    def __del__(self):
        """Деструктор - закрывает соединение при уничтожении объекта"""
        self.close()


# class Storage:
#     def __init__(self, logger: Logger):
#         config = get_db_config(logger=logger)
#         try:
#             conn = psycopg2.connect(
#                 host=config['host'],
#                 port=config['port'],
#                 dbname=config['database'],
#                 user=config['user'],
#                 password=config['password'],
#                 # connect_timeout=10  # Таймаут подключения 10 секунд
#             )
#             # logger.info("Successfully connected to data base")
#             self.connection = conn
#         except psycopg2.Error as e:
#             errtext = f"Data base connection error: {str(e)}"
#             logger.error(errtext)
#             raise Exception(errtext)

#     def get_db_connection(self):
#         return self.connection
