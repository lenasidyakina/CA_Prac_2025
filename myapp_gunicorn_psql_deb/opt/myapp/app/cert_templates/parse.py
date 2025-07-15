def file_to_dict(filename):
    result = {}
    with open(filename, 'r') as file:
        for line in file:
            # Удаляем пробелы в начале и конце строки
            line = line.strip()
            # Пропускаем пустые строки
            if not line:
                continue
            # Разделяем строку по первому знаку "="
            key, value = line.split('=', 1)
            # Удаляем возможные пробелы вокруг ключа и значения
            result[key.strip()] = value.strip()
    return result
