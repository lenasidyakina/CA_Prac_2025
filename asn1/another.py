from pyasn1.type import tag
from pyasn1.codec.ber import decoder, encoder
from pyasn1.codec.ber.eoo import EndOfOctets
import base64
from pyasn1.type import univ

def block_to_raw_bytes(data_block: bytes) -> bytes:
    # Декодируем первый элемент, чтобы получить его длину
    asn1_object, remaining = decoder.decode(data_block, asn1Spec=univ.Any())
    
    # Вычисляем длину декодированного блока
    encoded_length = len(data_block) - len(remaining)
    
    # Возвращаем сырые байты (тег + длина + значение)
    return data_block[:encoded_length]


if __name__ == '__main__':
    pem_file_path = './csr/full.p10'
    with open(pem_file_path, 'r') as pem_file:
        pem_csr = pem_file.read()

    # Удаляем лишние символы и декодируем Base64
    pem_lines = [line.strip() for line in pem_csr.split('\n') if line.strip()]
    pem_body = ''.join(pem_lines[1:-1])  # Убираем BEGIN/END строки
    der_csr = base64.b64decode(pem_body)
    block_to_raw_bytes(der_csr)