import ctypes
import os

class BicryWrapper:
    def __init__(self, lib_path='./libbicry_openkey.so', param=None):
        """
        Инициализация обертки для работы с криптографической библиотекой
        :param lib_path: путь к скомпилированной C-библиотеке
        """
        try:
            self.lib = ctypes.CDLL(lib_path)
        except OSError as e:
            raise RuntimeError(f"Failed to load library: {e}") from e
        except TypeError as e:
            raise RuntimeError(f"Uncorrect argument: {e}") from e

        self._initialized = False  # Флаг инициализации
        
        # Настраиваем прототип C-функции
        self.lib.init_bicr.restype = ctypes.c_int  # Код возврата
        self.lib.init_bicr.argtypes = []

        self.lib.check_param.restype = ctypes.c_int  # Код возврата
        self.lib.check_param.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_bool)
        ]

        self.lib.uninit_bicr.restype = ctypes.c_int  # Код возврата
        self.lib.uninit_bicr.argtypes = []

        self.lib.generate_keypair.restype = ctypes.c_int  # Код возврата
        self.lib.generate_keypair.argtypes = [
            ctypes.c_int,              # Параметр криптографического алгоритма
            ctypes.c_char_p,              # userid (строка)
            ctypes.POINTER(ctypes.c_ubyte)  # указатель на буфер для открытого ключа (64 байт)
        ]

        self.lib.compare_keys.restype = ctypes.c_int  # Код возврата
        self.lib.compare_keys.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), # указатель на буфер c открытым ключом (64 байт)
            ctypes.c_size_t                 # размер передаваемого ключа
        ]

        self.lib.electronic_signature.restype = ctypes.c_int  # Код возврата
        self.lib.electronic_signature.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), # Буфер для подписи
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t
        ]

        self.lib.get_elgkey_with_password.restype = ctypes.c_int  # Код возврата
        self.lib.get_elgkey_with_password.argtypes = [
            ctypes.POINTER(ctypes.c_char), # Буфер для пароля
            ctypes.POINTER(ctypes.c_ubyte) # Буфер для кдючевой информации
        ]

        # Инициализация библиотеки
        result = self.lib.init_bicr()
        if result != 0:
            raise RuntimeError(f"init_bicr failed with error: {result}")

        if param != None:
            check_flag = ctypes.c_bool(False)
            result = self.lib.check_param(param, ctypes.byref(check_flag))

            if result != 0:
                raise RuntimeError(f"check_param failed with error: {result}")
            elif check_flag.value:
                self.param = param
            else:
                raise RuntimeError(f"incorrect param: {param}")
        else:
            self.param = None

        self._initialized = True
        
    def __del__(self):
        """Деструктор - автоматическая деинициализация при удалении объекта"""
        self._uninit()

    def _uninit(self):
        """Внутренняя функция деинициализации"""
        if self._initialized:
            result = self.lib.uninit_bicr()
            if result != 0:
                print(f"Warning: uninit_bicr failed ({result})")    # В деструкторе нельзя выбрасывать исключения
        self._initialized = False

    def close(self):
        """Явная деинициализация ресурсов"""
        self._uninit()

    def generate_keypair(self, userid: str, param) -> bytes:
        """
        Экспорт открытого ключа для указанного пользователя
        
        :param userid: идентификатор пользователя (до 32 символов)
        :return: открытый ключ (64 байт)
        :raises ValueError: при недопустимом userid
        :raises RuntimeError: при ошибке в C-библиотеке
        """
        if not self._initialized:
            raise RuntimeError("Library not initialized")

        # Проверяем длину userid
        if len(userid) == 0 or len(userid) > 32:
            raise ValueError("UserID must be 1-32 characters")

        # Проверяем значения параметра криптографического алгоритма
        if param not in {49, 50, 51, 65, 66, 67, 68, 97, 98, 99}:
            raise ValueError("Cryptographic algorithm parametr must take one of the following values: 49-51, 65-68, 97-99")

        # Определяем размер открытого ключа
        key_size = 128 if param in {49, 50, 51} else 64
        # Создаем буфер для ключа (64 байт)
        key_buffer = (ctypes.c_ubyte * key_size)()
        
        # Преобразуем userid в байты
        userid_bytes = userid.encode('utf-8')
        
        # Вызываем C-функцию
        result = self.lib.generate_keypair(
            param,         #Параметр криптографического алгоритма
            userid_bytes,  # userid
            key_buffer     # буфер для ключа
        )
        
        if result != 0:
            raise RuntimeError(f"Crypto operation failed with error code: {result}")
        
        self.param = param
        
        # Преобразуем буфер в байты
        return bytes(key_buffer)

    def electronic_signature(self, cert_data: bytes) -> bytes:
        """
        Подпись буфера ЭП
        
        :raises RuntimeError: при ошибке в C-библиотеке
        """

        if not self._initialized:
            raise RuntimeError("Library not initialized")

        if not self.param:
            raise RuntimeError("Keypair not created")

        # Определяем размер открытого ключа
        signature_size = 128 if self.param in {49, 50, 51} else 64

        # Создаем буфер для подписи (64 или 128 байт)
        es_buffer = (ctypes.c_ubyte * signature_size)()

        # Создаем буфер для данных сертификата
        cert_buffer = (ctypes.c_ubyte * len(cert_data)).from_buffer_copy(cert_data)

        # Вызываем C-функцию для подписи 
        result = self.lib.electronic_signature(
            es_buffer,
            cert_buffer,
            len(cert_data),
            self.param
        )
        
        if result != 0:
            raise RuntimeError(f"Crypto operation failed with error code: {result}")

        # Преобразуем буфер в байты
        return bytes(es_buffer)
        
    def get_private_key_with_password(self) -> str:
        """
        Получение пароля из внутреннего буфера библиотеки
        :return: пароль для закрытого ключа (6 символов)
        :raises RuntimeError: если произошла ошибка
        """
        # Создаем буфер для пароля (6 байт + 1 для нуль-терминатора)
        pw_buffer = (ctypes.c_char * 7)()  # 6 символов + '\0'

        # Создаем буфер для ключевой инфорамации
        private_key_buffer = (ctypes.c_ubyte * 69)() 
        
        # Вызываем C-функцию
        result = self.lib.get_elgkey_with_password(pw_buffer, private_key_buffer)
        
        if result != 0:
            raise RuntimeError(f"Failed to get password, error code: {result}")
        
        # Преобразуем в строку (автоматически остановится на нуль-терминаторе)
        return pw_buffer.value.decode('ascii'), bytes(private_key_buffer)

    def compare_keys(self, public_key: bytes) -> bool:
        # Создаем буфер для ключа
        public_key_buffer = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
        
        # Вызываем C-функцию
        result = self.lib.compare_keys(
            public_key_buffer, 
            len(public_key_buffer))
        
        # Обработка результатов
        if result == 0:
            return True
        elif result == 1:
            return False
        else:
            raise RuntimeError(f"Ошибка сравнения ключей: {result}")


# Пример использования
if __name__ == "__main__":
    wrapper = None
    try:
        wrapper = BicryWrapper(lib_path='./libbicry_openkey.so', param=None)


        public_key = wrapper.generate_keypair("Ivanov", param=98)
        #print(f"Public key: {public_key.hex()}")

        result = wrapper.compare_keys(public_key)     # соответствие закрытого ключа открытому

        password, private_key = wrapper.get_private_key_with_password()
        #print(f"Password: {password}")

        wrapper.close()
     
        wrapper = BicryWrapper(lib_path='./libbicry_openkey.so', param=98)
        
        # Пример чтения сертификата из файла (для примера)
        with open('tbs.der', 'rb') as f:
            cert_data = f.read()
        
        es = wrapper.electronic_signature(cert_data)    #в качсетве аргумента буфер для подписи
        #print(f"Signature: {es.hex()}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if wrapper:
            wrapper.close()  # Явный вызов деинициализации