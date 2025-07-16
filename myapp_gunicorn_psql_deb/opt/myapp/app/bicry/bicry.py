import ctypes
import os
import logging 
import traceback

# Настройка логирования
logger = logging.getLogger('BicryWrapper')
logger.setLevel(logging.INFO)

# Создаем обработчик с UTF-8 кодировкой
file_handler = logging.FileHandler('nikita.log', mode='a', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Отключаем дублирование в корневой логгер
logger.propagate = False

class BicryWrapper:
    def __init__(self, lib_path='./libbicry_openkey.so', param=None):
        """
        Инициализация обертки для работы с криптографической библиотекой
        :param lib_path: путь к скомпилированной C-библиотеке
        """
        logger.info(f"Initializing BicryWrapper with lib_path={lib_path}, param={param}")
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

        self.lib.check_param.restype = ctypes.c_int
        self.lib.check_param.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_bool)
        ]

        self.lib.uninit_bicr.restype = ctypes.c_int
        self.lib.uninit_bicr.argtypes = []

        self.lib.generate_keypair.restype = ctypes.c_int
        self.lib.generate_keypair.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte)
        ]

        self.lib.compare_keys.restype = ctypes.c_int
        self.lib.compare_keys.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t
        ]

        self.lib.electronic_signature.restype = ctypes.c_int
        self.lib.electronic_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.c_int
        ]

        self.lib.get_elgkey_with_password.restype = ctypes.c_int
        self.lib.get_elgkey_with_password.argtypes = [
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_ubyte)
        ]

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

        try:
            if param is not None:
                logger.info(f"Checking parameter: {param}")
                check_flag = ctypes.c_bool(False)
                result = self.lib.check_param(param, ctypes.byref(check_flag))

                if result != 0:
                    logger.error(f"check_param failed with error: {result}")
                    raise RuntimeError(f"check_param failed with error: {result}")
                
                if check_flag.value:
                    logger.info(f"Parameter validated: {param}")
                    self.param = param
                else:
                    logger.error(f"Invalid parameter: {param}")
                    raise RuntimeError(f"incorrect param: {param}")
            else:
                logger.info("No parameter provided, using default")
                self.param = None
        except Exception as e:
            logger.error(f"Parameter check failed: {e}\n{traceback.format_exc()}")
            self._uninit()
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

    def generate_keypair(self, userid: str, param) -> bytes:
        """
        Генерация ключевой пары
        """
        logger.info(f"Generating keypair for userid='{userid}', param={param}")
        try:
            if not self._initialized:
                logger.error("Library not initialized during keypair generation")
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

            # Создание буфера
            key_size = 128 if param in {49, 50, 51} else 64
            key_buffer = (ctypes.c_ubyte * key_size)()
            userid_bytes = userid.encode('utf-8')
            
            # Вызов C-функции
            logger.debug(f"Calling generate_keypair with param={param}, userid={userid}")
            result = self.lib.generate_keypair(param, userid_bytes, key_buffer)
            
            if result != 0:
                error_msg = f"generate_keypair failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            self.param = param
            key_bytes = bytes(key_buffer)
            logger.info(f"Keypair generated successfully, key size={len(key_bytes)} bytes")
            return key_bytes
        except Exception as e:
            logger.error(f"Error in generate_keypair: {e}\n{traceback.format_exc()}")
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
                self.param  # Добавлен параметр
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
        
    def get_private_key_with_password(self) -> tuple:
        """
        Получение пароля и закрытого ключа
        """
        logger.info("Retrieving private key with password")
        try:
            pw_buffer = (ctypes.c_char * 7)()
            private_key_buffer = (ctypes.c_ubyte * 69)()
            
            logger.debug("Calling get_elgkey_with_password")
            result = self.lib.get_elgkey_with_password(pw_buffer, private_key_buffer)
            
            if result != 0:
                error_msg = f"get_elgkey_with_password failed with error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            password = pw_buffer.value.decode('ascii')
            private_key = bytes(private_key_buffer)
            logger.info("Private key and password retrieved successfully")
            return password, private_key
        except Exception as e:
            logger.error(f"Error in get_private_key_with_password: {e}\n{traceback.format_exc()}")
            raise

    def compare_keys(self, public_key: bytes) -> bool:
        """
        Сравнение ключей
        """
        logger.info("Comparing keys")
        try:
            public_key_buffer = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
            
            logger.debug(f"Calling compare_keys with key size={len(public_key)} bytes")
            result = self.lib.compare_keys(public_key_buffer, len(public_key_buffer))
            
            if result == 0:
                logger.info("Keys match")
                return True
            elif result == 1:
                logger.warning("Keys do not match")
                return False
            else:
                error_msg = f"Key comparison error: {result}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
        except Exception as e:
            logger.error(f"Error in compare_keys: {e}\n{traceback.format_exc()}")
            raise


# Пример использования
if __name__ == "__main__":
    wrapper = None
    try:
        wrapper = BicryWrapper(lib_path='./libbicry_openkey.so', param=None)

        public_key = wrapper.generate_keypair("Ivanov", param=98)
        
        result = wrapper.compare_keys(public_key)
        
        password, private_key = wrapper.get_private_key_with_password()
        
        wrapper.close()
     
        wrapper = BicryWrapper(lib_path='./libbicry_openkey.so', param=98)
        
        with open('tbs.der', 'rb') as f:
            cert_data = f.read()
        
        es = wrapper.electronic_signature(cert_data)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if wrapper:
            wrapper.close()