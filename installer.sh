#!/bin/bash

# Функция для настройки репозиториев Astra Linux
configure_astra_repos() {
    echo "=== Настройка репозиториев Astra Linux ==="
    SOURCES_FILE="/etc/apt/sources.list"
    BACKUP_FILE="/etc/apt/sources.list.bak"

    # Функция для автоматической настройки репозиториев
    configure_repos_auto() {
        echo "Автоматическая настройка репозиториев..."

        # Создаем резервную копию
        cp "$SOURCES_FILE" "$BACKUP_FILE"
        echo "Создана резервная копия: $BACKUP_FILE"

        # Комментируем все существующие репозитории
        sed -i 's/^deb/#deb/g' "$SOURCES_FILE"

        # Добавляем официальные репозитории Astra Linux
        cat > "$SOURCES_FILE" <<EOL
# Official Astra Linux repositories
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-main/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-update/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-base/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-extended/ 1.7_x86-64 main contrib non-free

# Закомментировать CD-репозиторий
#deb cdrom:[OS Astra Linux 1.7.5 1.7_x86-64 DVD ]/ 1.7_x86-64 contrib main non-free
EOL

        echo "Репозитории успешно настроены автоматически"
    }

    # Функция для ручной настройки репозиториев
    configure_repos_manual() {
        echo "Ручная настройка репозиториев..."
        echo "Открываю файл $SOURCES_FILE для редактирования"
        echo "Пожалуйста, убедитесь, что в файле присутствуют следующие строки (могут быть другие названия путей в зависимости от версии astra):"
        echo
        echo "deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-main/ 1.7_x86-64 main contrib non-free"
        echo "deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-update/ 1.7_x86-64 main contrib non-free"
        echo "deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-base/ 1.7_x86-64 main contrib non-free"
        echo "deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-extended/ 1.7_x86-64 main contrib non-free"
        echo "#deb cdrom:[OS Astra Linux 1.7.5 1.7_x86-64 DVD ]/ 1.7_x86-64 contrib main non-free"
        echo
        read -p "Нажмите Enter для продолжения..."

        # Создаем резервную копию
        cp "$SOURCES_FILE" "$BACKUP_FILE"
        echo "Создана резервная копия: $BACKUP_FILE"

        # Открываем редактор
        nano "$SOURCES_FILE"

        echo "Ручная настройка завершена"
    }

    # Основной код настройки репозиториев
    echo "Обнаружены неправильные или отсутствующие репозитории Astra Linux"
    echo "Выберите метод настройки:"
    echo "1) Автоматическая настройка (рекомендуется только если версия astra 1.7)"
    echo "2) Ручная настройка"
    echo "3) Пропустить настройку репозиториев (если файл уже правильно настроен)"

    while true; do
        read -p "Ваш выбор [1-3]: " choice
        case $choice in
            1)
                configure_repos_auto
                break
                ;;
            2)
                configure_repos_manual
                break
                ;;
            3)
                echo "Пропускаю настройку репозиториев"
                break
                ;;
            *)
                echo "Неверный выбор, попробуйте снова"
                ;;
        esac
    done
}

# Функция для установки .deb пакета
install_deb_package() {
    local deb_file="myapp_gunicorn_psql_deb.deb"

    echo "=== Установка .deb пакета ==="

    # Проверяем, существует ли файл
    if [ ! -f "$deb_file" ]; then
        echo "Ошибка: Файл $deb_file не найден в текущей директории!"
        return 1
    fi

    echo "Обновление списка пакетов..."
    sudo apt update

    echo "Установка пакета $deb_file..."
    sudo apt install -y "./$deb_file"

    if [ $? -eq 0 ]; then
        echo "Пакет $deb_file успешно установлен!"
    else
        echo "Ошибка при установке пакета $deb_file"
        return 1
    fi
}

# Основное выполнение скрипта
configure_astra_repos
install_deb_package

echo "=== Скрипт завершен ==="
exit 0
