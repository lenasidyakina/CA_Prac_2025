# CA_Prac_2025
Зайдите в терминал
1.Введите команду
sudo nano /etc/apt/sources.list
2.В файле проверьте чтобы строчки
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-main/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-update/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-base/ 1.7_x86-64 main contrib non-free
deb https://download.astralinux.ru/astra/stable/1.7_x86-64/repository-extended/ 1.7_x86-64 main contrib non-free
были раскомментированы, а строка
#deb cdrom:[OS Astra Linux 1.7.5 1.7_x86-64 DVD ]/ 1.7_x86-64 contrib main non-free
закоментирована
3.В случае если вы до этого использовали старую  версию пакета введите команду
sudo apt purge myapp-asta
4.Запустите полученный  deb пакет командой
sudo apt install ./myapp_gunicorn_psql_deb.deb 
5.Введите имя пользователя бд, пароль и название бд в которой будет создана таблица отозванных сертификатов.
В случае если пользователь уже существует, но введён другой пароль - пароль обновиться
6.Откройте браузер и введите адрес
http://localhost
