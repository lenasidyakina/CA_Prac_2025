import ctypes
import os
import logging 
import traceback
from logging.handlers import SysLogHandler
import socket
import sys

# Настройка логгера должна быть ДО создания экземпляра BicryWrapper
# logger = logging.getLogger('bicry_c')
# logger.setLevel(logging.INFO)

# syslog_handler = SysLogHandler(
#     address='/dev/log', 
#     facility='user',
#     socktype=socket.SOCK_DGRAM
# )

# syslog_handler.setFormatter(logging.Formatter('%(name)s: %(levelname)s %(message)s'))
# logger.addHandler(syslog_handler)

log_dir = '/var/log/myapp/'
os.makedirs(log_dir, exist_ok=True)
lof_file = os.path.join(log_dir, 'bicry.log')
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler(lof_file),
#         logging.StreamHandler(sys.stdout)
#     ]
# )
logger = logging.getLogger('Bicry')
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(lof_file)
file_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
)
logger.addHandler(file_handler)

'''
#При запуске просто приложения:
#В файл
#/etc/rsyslog.d/bicry.conf
#поместить:
#if $programname == 'bicry_c' then /var/log/bicry.log
#& stop

#sudo touch /var/log/bicry.log
#sudo chown syslog:adm /var/log/bicry.log    //Права chown syslog:adm гарантируют, что rsyslog сможет писать в файл лога.
#sudo chmod 664 /var/log/bicry.log
#sudo systemctl restart rsyslog

# Для деб пакета 
# 1) postinst скрипт
#!/bin/sh
# Скопировать конфиг rsyslog
# cp /path/to/bicry.conf /etc/rsyslog.d/

# Создать файл лога с правильными правами
#touch /var/log/bicry.log
#chown root:adm /var/log/bicry.log
#chmod 664 /var/log/bicry.log

# Перезапустить rsyslog
#systemctl restart rsyslog

# 2) содержимое bicry.conf
# Правила для приложения Bicry
#if $programname == 'bicry_c' then /var/log/bicry.log
#& stop

# 3) prerm скрипт
#!/bin/sh
# Удалить конфиг
#rm /etc/rsyslog.d/bicry.conf

# (Опционально) Удалить лог-файл
#rm /var/log/bicry.log

# Перезапустить rsyslog
#systemctl restart rsyslog
'''

class BicryWrapper:
    def __init__(self, lib_path='./libbicry_openkey.so'):
        """
        Инициализация обертки для работы с криптографической библиотекой
        :param lib_path: путь к скомпилированной C-библиотеке
        """
        logger.info(f"Initializing BicryWrapper with lib_path={lib_path}")
        try:
            self.lib = ctypes.CDLL(lib_path)
            logger.info(f"Library '{lib_path}' loaded successfully")
        except OSError as e:
            logger.error(f"Failed to load library: {e}\n{traceback.format_exc()}")
            raise RuntimeError(f"Failed to load library: {e}") from e
        except TypeError as e:
            logger.error(f"Uncorrect argument: {e}\n{traceback.format_exc()}")
            raise RuntimeError(f"Uncorrect argument: {e}") from e

        self._initialized = False  # Флаг инициализации
        
        # Настраиваем прототип C-функции
        self.lib.init_bicr.restype = ctypes.c_int
        self.lib.init_bicr.argtypes = []

        self.lib.uninit_bicr.restype = ctypes.c_int
        self.lib.uninit_bicr.argtypes = []

        self.lib.generate_temp_keypair.restype = ctypes.c_int
        self.lib.generate_temp_keypair.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte)
        ]

        self.lib.temp_electronic_signature.restype = ctypes.c_int
        self.lib.temp_electronic_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.c_int
        ]

        self.lib.change_active_cert.restype = ctypes.c_int
        self.lib.change_active_cert.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_bool),
            ctypes.POINTER(ctypes.c_bool)
        ]

        self.lib.electronic_signature.restype = ctypes.c_int
        self.lib.electronic_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.c_int
        ]

        logger.info("start init_bicr()")
        # Инициализация библиотеки
        try:
            result = self.lib.init_bicr()
            if result != 0:
                logger.error(f"init_bicr failed with error: {result}")
                raise RuntimeError(f"init_bicr failed with error: {result}")
            logger.info("init_bicr completed successfully")
        except Exception as e:
            logger.error(f"Error in init_bicr: {e}\n{traceback.format_exc()}")
            raise

        self._initialized = True
        logger.info("BicryWrapper initialized successfully")
        
    def __del__(self):
        """Деструктор - автоматическая деинициализация при удалении объекта"""
        self._uninit()

    def _uninit(self):
        """Внутренняя функция деинициализации"""
        if self._initialized:
            try:
                result = self.lib.uninit_bicr()
                if result != 0:
                    logger.warning(f"uninit_bicr returned non-zero code: {result}")
                else:
                    logger.info("Library uninitialized successfully")
            except Exception as e:
                logger.error(f"Error during uninit: {e}\n{traceback.format_exc()}")
            finally:
                self._initialized = False

    def close(self):
        """Явная деинициализация ресурсов"""
        self._uninit()

    def generate_temp_keypair(self, userid: str, param: int) -> tuple:
        """
        Генерация временной ключевой пары
        """
        logger.info(f"Generating keypair for userid='{userid}', param={param}")
        try:
            if not self._initialized:
                logger.error("Library not initialized during temp_keypair generation")
                raise RuntimeError("Library not initialized")

            # Проверка userid
            if len(userid) == 0 or len(userid) > 32:
                error_msg = "UserID must be 1-32 characters"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Проверка параметра
            valid_params = {49, 50, 51, 65, 66, 67, 68, 97, 98, 99}
            if param not in valid_params:
                error_msg = f"Invalid crypto parameter: {param}, must be one of {valid_params}"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Создание буфера под пароль
            pw_buffer = (ctypes.c_char * 7)()

            # Создание буфер под private key
            private_key_buffer = (ctypes.c_ubyte * 69)()

            # Создание буфера под public key
            key_size = 128 if param in {49, 50, 51} else 64
            key_buffer = (ctypes.c_ubyte * key_size)()

            userid_bytes = userid.encode('utf-8')
            
            # Вызов C-функции
            logger.debug(f"Calling generate_temp_keypair with param={param}, userid={userid}")
            result = self.lib.generate_temp_keypair(param, userid_bytes, pw_buffer, private_key_buffer, key_buffer)
            
            if result != 0:
                error_msg = f"generate_temp_keypair failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            self.temp_param = param
            password = pw_buffer.value.decode('ascii')
            private_key = bytes(private_key_buffer)
            key_bytes = bytes(key_buffer)

            logger.info(f"Keypair generated successfully, public_key size={len(key_bytes)} bytes")
            return password, private_key, key_bytes
        except Exception as e:
            logger.error(f"Error in generate_temp_keypair: {e}\n{traceback.format_exc()}")
            raise 

    def temp_electronic_signature(self, cert_data: bytes) -> bytes:
        """
        Создание электронной подписи для временного корневого
        """
        logger.info("Creating temp electronic signature")
        try:
            if not self._initialized:
                logger.error("Library not initialized during temp signature creation")
                raise RuntimeError("Library not initialized")

            if not self.temp_param:
                logger.error("Temp keypair not created, cannot create temp signature")
                raise RuntimeError("Temp keypair not created")

            signature_size = 128 if self.temp_param in {49, 50, 51} else 64
            es_buffer = (ctypes.c_ubyte * signature_size)()
            cert_buffer = (ctypes.c_ubyte * len(cert_data)).from_buffer_copy(cert_data)

            logger.debug(f"Calling temp_electronic_signature with data size={len(cert_data)} bytes")
            result = self.lib.temp_electronic_signature(
                es_buffer,
                cert_buffer,
                len(cert_data),
                self.temp_param 
            )
            
            if result != 0:
                error_msg = f"temp_electronic_signature failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            signature = bytes(es_buffer)
            logger.info(f"Temp signature created successfully, size={len(signature)} bytes")
            return signature
        except Exception as e:
            logger.error(f"Error in temp_electronic_signature: {e}\n{traceback.format_exc()}")
            raise
        
    def change_active_cert(self, param: int, password, private_key: bytes, public_key: bytes):
        """
        Сделать корневой сертификат активным (сохранение private_key, проверка параметров алгоритма, проверка открытого ключа)
        """
        logger.info(f"Активировать корневой сертификат for param={param}")
        try:
            if not self._initialized:
                logger.error("Library not initialized during change_active_certivicate")
                raise RuntimeError("Library not initialized")

            # Проверка параметра
            valid_params = {49, 50, 51, 65, 66, 67, 68, 97, 98, 99}
            if param not in valid_params:
                error_msg = f"Invalid crypto parameter: {param}, must be one of {valid_params}"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Валидация пароля
            if not isinstance(password, str):
                raise TypeError("Password must be a string")
            
            # Преобразование пароля в байты (UTF-8)
            password_bytes = password.encode('utf-8')
            
            # Максимальная длина пароля - 6 байт (буфер 7 байт включает нуль-терминатор)
            if len(password_bytes) > 6:
                error_msg = "Password too long, max 6 characters"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Запрет нулевых байтов в пароле (иначе C-строка обрежется)
            if b'\x00' in password_bytes:
                error_msg = "Password must not contain null bytes"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Создание буфера под пароль (7 байт с нуль-терминатором)
            pw_buffer = ctypes.create_string_buffer(7)  # Инициализирован нулями

            # Копируем байты пароля (без нуль-терминатора)
            ctypes.memmove(pw_buffer, password_bytes, len(password_bytes))
            # После копирования в конце остаётся 0 (нуль-терминатор из инициализации)

            # Создание буфера под private key
            if len(private_key) != 69:
                error_msg = f"Private key must be 69 bytes, got {len(private_key)}"
                logger.error(error_msg)
                raise ValueError(error_msg)
            private_key_buffer = (ctypes.c_ubyte * 69)(*private_key)

            # Создание буфера под открытый ключ
            public_key_buffer = (ctypes.c_ubyte * len(public_key))(*public_key)

            # Переменная для проверка параметра алгоритма
            check_param_flag = ctypes.c_bool(False)

            # Переменная для проверка соответсвия открытого ключа
            check_openkey_flag = ctypes.c_bool(False)
            
            logger.debug(f"Calling change_active_cert with param={param}")
            result = self.lib.change_active_cert(
                param,
                pw_buffer,
                private_key_buffer,
                public_key_buffer,
                len(public_key_buffer),
                ctypes.byref(check_param_flag),
                ctypes.byref(check_openkey_flag)
            )

            if result != 0:
                error_msg = f"change_active_cert failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            if not check_param_flag.value:
                logger.error(f"Invalid parameter: {param}")
                raise RuntimeError(f"incorrect param: {param}")
            elif not check_openkey_flag.value:
                logger.error(f"Incorrect openkey")
                raise RuntimeError(f"incorrect openkey")
            else:
                logger.info(f"Parameter validated: {param}")
                logger.info(f"Open_key validated")
                self.param = param
                
            logger.info(f"Change active certificate done successfully")

        except Exception as e:
            logger.error(f"Error in change_active_cert: {e}\n{traceback.format_exc()}")
            raise

    def electronic_signature(self, cert_data: bytes) -> bytes:
        """
        Создание электронной подписи
        """
        logger.info("Creating electronic signature")
        try:
            if not self._initialized:
                logger.error("Library not initialized during signature creation")
                raise RuntimeError("Library not initialized")

            if not self.param:
                logger.error("Keypair not created, cannot create signature")
                raise RuntimeError("Keypair not created")

            signature_size = 128 if self.param in {49, 50, 51} else 64
            es_buffer = (ctypes.c_ubyte * signature_size)()
            cert_buffer = (ctypes.c_ubyte * len(cert_data)).from_buffer_copy(cert_data)

            logger.debug(f"Calling electronic_signature with data size={len(cert_data)} bytes")
            result = self.lib.electronic_signature(
                es_buffer,
                cert_buffer,
                len(cert_data),
                self.param 
            )
            
            if result != 0:
                error_msg = f"electronic_signature failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            signature = bytes(es_buffer)
            logger.info(f"Signature created successfully, size={len(signature)} bytes")
            return signature
        except Exception as e:
            logger.error(f"Error in electronic_signature: {e}\n{traceback.format_exc()}")
            raise    


# Пример использования
if __name__ == "__main__":
    wrapper = None
    try:
        wrapper = BicryWrapper(lib_path='./libbicry_openkey.so')

        password, private_key, public_key = wrapper.generate_temp_keypair("Ivanov", param=98)

        with open('tbs.der', 'rb') as f:
            cert_data = f.read()
        
        es = wrapper.temp_electronic_signature(cert_data)
        #print(f"Signature: {es.hex()}")

        wrapper.change_active_cert(param=98, password=password, private_key=private_key, public_key=public_key)

        password, private_key, public_key = wrapper.generate_temp_keypair("Ivanov", param=98)

        with open('tbs.der', 'rb') as f:
            cert_data = f.read()  
        
        es = wrapper.temp_electronic_signature(cert_data)
        #print(f"Signature: {es.hex()}")

        with open('tbs.der', 'rb') as f:
            cert_data = f.read()
        
        es = wrapper.electronic_signature(cert_data)
        
        wrapper.close()   
        logger.removeHandler(syslog_handler)
        
    except Exception as e:
        logger.critical(f"Critical error in demo: {e}\n{traceback.format_exc()}")
        print(f"Error: {e}")
    finally:
        if wrapper:
            wrapper.close()
