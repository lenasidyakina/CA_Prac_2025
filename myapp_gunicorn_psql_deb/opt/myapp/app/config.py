from configparser import ConfigParser
from logging import Logger

def get_db_config(logger: Logger):
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
        logger.error(f"Error reading data bases's configuration file: {str(e)}")
        raise