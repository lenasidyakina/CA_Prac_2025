import ctypes
import os

class BicryWrapper:
    def __init__(self, param=98, lib_path='libbicry_openkey.so'):
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

        self.lib.export_keys.restype = ctypes.c_int  # Код возврата
        self.lib.export_keys.argtypes = [
            ctypes.c_char_p,              # userid (строка)
            ctypes.POINTER(ctypes.c_ubyte)  # Буфер для открытого ключа (256 байт)
        ]

        self.lib.electronic_signature.restype = ctypes.c_int  # Код возврата
        self.lib.electronic_signature.argtypes = []

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

    def export_public_key(self, userid: str) -> bytes:
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
        result = self.lib.export_keys(
            userid_bytes,  # userid
            key_buffer     # буфер для ключа
        )
        
        if result != 0:
            raise RuntimeError(f"Crypto operation failed with error code: {result}")
        
        # Преобразуем буфер в байты
        return bytes(key_buffer)

    def electronic_signature(self):
        """
        Подпись буфера ЭП
        
        :raises RuntimeError: при ошибке в C-библиотеке
        """

        if not self._initialized:
            raise RuntimeError("Library not initialized")
        
        # Вызываем C-функцию
        result = self.lib.electronic_signature()
        
        if result != 0:
            raise RuntimeError(f"Crypto operation failed with error code: {result}")
        

# Пример использования
if __name__ == "__main__":
    wrapper = None
    try:
        wrapper = BicryWrapper()
        
        public_key = wrapper.export_public_key("Ivanov")
        print(f"Public key: {public_key.hex()}")
        
        wrapper.electronic_signature()
        print("Signature created")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if wrapper:
            wrapper.close()  # Явный вызов деинициализации