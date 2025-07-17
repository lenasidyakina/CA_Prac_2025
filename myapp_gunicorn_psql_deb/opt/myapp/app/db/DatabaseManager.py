import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor
from configparser import ConfigParser
from contextlib import contextmanager
from asn1_parser.asn1_parse import generate_serial_num
from asn1_parser.models.RevokedCertificates import RevokedCertificates, CRLReasonCode


class DatabaseManager:
    def __init__(self, logger):
        self._connection = None
        self.logger = logger
        self._connect()
        
    def _connect(self):
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

    # def get_revoked_certificates(self):
    #     revoked_certificates = []
    #     with self.get_cursor() as cursor:
    #         # cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE")
    #         cursor.execute("SELECT serial_number, revoke_date, revoke_reason, invalidity_date FROM certificates WHERE is_revoked = TRUE and send_to_ca = FALSE")
            
    #         for row in cursor.fetchall():
    #             serialNumber = int(row[0])
    #             revocationDate = row[1]
    #             crlReasonCode = CRLReasonCode[row[2]] if row[2] else CRLReasonCode.unspecified
    #             invalidityDate = row[3]
                
    #             revoked_certificates.append(
    #                 RevokedCertificates(
    #                     serialNumber=serialNumber,
    #                     revocationDate=revocationDate,
    #                     crlReasonCode=crlReasonCode,
    #                     invalidityDate=invalidityDate
    #                 )
    #             )
    #     return revoked_certificates
    def get_revoked_certificates(self):
        revoked_certificates = []
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT serial_number, revoke_date, revoke_reason, invalidity_date 
                FROM certificates 
                WHERE is_revoked = TRUE AND send_to_ca = FALSE
            """)
            
            serial_numbers = []
            for row in cursor.fetchall():
                serial_str = row[0]
                try:
                    serialNumber = int(serial_str)
                    
                    revoked_certificates.append(
                        RevokedCertificates(
                            serialNumber=serialNumber,
                            revocationDate=row[1],
                            crlReasonCode=CRLReasonCode[row[2]] if row[2] else CRLReasonCode.unspecified,
                            invalidityDate=row[3]
                        )
                    )
                    serial_numbers.append(serial_str)
                except ValueError:
                    self.logger.error(f"Invalid serial number format: {serial_str}")
                    continue
            
            # Обновляем каждый сертификат по отдельности
            if serial_numbers:
                updated_count = 0
                for serial in serial_numbers:
                    try:
                        cursor.execute("""
                            UPDATE certificates 
                            SET send_to_ca = TRUE 
                            WHERE serial_number = %s
                        """, (serial,))
                        updated_count += 1
                    except Exception as e:
                        self.logger.error(f"Failed to update certificate {serial}: {str(e)}")
                
                
        return revoked_certificates
    
    
    


    def insert_to_db(self, serial_number, source_serial_number):
        try:
            with self.get_cursor() as cursor:
                cursor.execute(
                    """INSERT INTO certificates 
                    VALUES (%s, false, null, null, null, %s, false)""",
                    (serial_number, source_serial_number)
                )
            return True
        except Exception as e:
            self.logger.error(f"Error while inserting certificate to database: {str(e)}")
            return False


    def close(self):
        if self._connection and not self._connection.closed:
            self._connection.close()
            self.logger.info("Database connection closed")
    
    def __del__(self):
        #Деструктор
        self.close()
