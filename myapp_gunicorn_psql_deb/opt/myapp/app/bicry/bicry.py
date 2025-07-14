import ctypes
import os

class BicryWrapper:
    def __init__(self, param=98, lib_path='./libbicry_openkey.so'):
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
        self.lib.init_bicr.argtypes = [
            ctypes.c_int              # Параметр криптографического алгоритма
        ]

        self.lib.uninit_bicr.restype = ctypes.c_int  # Код возврата
        self.lib.uninit_bicr.argtypes = []

        self.lib.generate_keypair.restype = ctypes.c_int  # Код возврата
        self.lib.generate_keypair.argtypes = [
            ctypes.c_char_p,              # userid (строка)
            ctypes.POINTER(ctypes.c_ubyte)  # указатель на буфер для открытого ключа (64 байт)
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
        result = self.lib.init_bicr(param)
        if result != 0:
            raise RuntimeError(f"init_bicr failed with error: {result}")

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

    def generate_keypair(self, userid: str) -> bytes:
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
        
        # Создаем буфер для ключа (64 байт)
        key_buffer = (ctypes.c_ubyte * 64)()
        
        # Преобразуем userid в байты
        userid_bytes = userid.encode('utf-8')
        
        # Вызываем C-функцию
        result = self.lib.generate_keypair(
            userid_bytes,  # userid
            key_buffer     # буфер для ключа
        )
        
        if result != 0:
            raise RuntimeError(f"Crypto operation failed with error code: {result}")
        
        # Преобразуем буфер в байты
        return bytes(key_buffer)

    def electronic_signature(self, cert_data: bytes) -> bytes:
        """
        Подпись буфера ЭП
        
        :raises RuntimeError: при ошибке в C-библиотеке
        """

        if not self._initialized:
            raise RuntimeError("Library not initialized")

        # Создаем буфер для подписи (64 байт)
        es_buffer = (ctypes.c_ubyte * 64)()

        # Создаем буфер для данных сертификата
        cert_buffer = (ctypes.c_ubyte * len(cert_data)).from_buffer_copy(cert_data)

        # Вызываем C-функцию
        result = self.lib.electronic_signature(
            es_buffer,
            cert_buffer,
            len(cert_data)
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


# Пример использования
if __name__ == "__main__":
    wrapper = None
    try:
        wrapper = BicryWrapper(param=98, lib_path='libbicry_openkey.so')

        public_key = wrapper.generate_keypair("Ivanov")
        #print(f"Public key: {public_key.hex()}")

        password, private_key = wrapper.get_private_key_with_password()
        #print(f"Password: {password}")

        wrapper.close()
     
        wrapper = BicryWrapper(param=98, lib_path='./libbicry_openkey.so')
        
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