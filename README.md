# Инструкция по установке CA_Prac_2025

## 1. Настройка репозиториев

Откройте файл sources.list для редактирования:
```bash
sudo nano /etc/apt/sources.list
```

Убедитесь, что в файле присутствуют следующие **активные** строки (без символа #):
```
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-main/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-update/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-base/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-extended/ 1.7_x86-64 main contrib non-free
```

И **закомментирована** строка с CD:
```
#deb cdrom:[OS Astra Linux 1.7.5 1.7_x86-64 DVD ]/ 1.7_x86-64 contrib main non-free
```

## 2. Удаление предыдущей версии (если установлена)

```bash
sudo apt purge myapp-asta
```

## 3. Установка нового пакета

```bash
sudo apt install ./myapp_gunicorn_psql_deb.deb
```

## 4. Настройка базы данных

Во время установки потребуется указать:
- Имя пользователя PostgreSQL
- Пароль пользователя
- Имя базы данных

> Примечание: Если пользователь уже существует, указанный пароль будет обновлен.

## 5. Проверка работоспособности

Откройте в веб-браузере:
```
http://localhost
```

---

**Важно!** Все команды должны выполняться с правами root (через sudo).
