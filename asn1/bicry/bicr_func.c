#define UNIX
#include "bcry.h"
#include "errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

H_INIT init_handle;
char password[7] = {0}; // 6 символов + '\0'

int init_bicr(int param) {
    // 1. Загрузка библиотеки, её инициализация и инициализация ДСЧ
    int result = cr_load_bicr_dll ("");

    if (result != ERR_OK){
        printf("Ошибка загрузки библиотеки: %d\n", result);
        return result;
    }

    int init_mode = 0;
    result =  cr_init(
        0, "", "", "", NULL, NULL,
        &init_mode, &init_handle);

    if (result != ERR_OK) {
        printf("Ошибка инициализации библиотеки: %d\n", result);
        return result;
    }

    // 2. Установка параметров библиотеки
    int option = 1;
    result = cr_set_param (
        init_handle,            //дескриптор H_INIT, возвращенный функцией cr_init() или дескриптор H_USER, возвращенный функцией cr_read_skey() или дескриптор H_PKEY, возвращенный функцией cr_pkey_load()
        option,             //номер опции, принимает значение 1
        param);             //значение опции option. для опции option=1: установка параметров криптографических алгоритмов – см. Приложение №3

    if (result != ERR_OK) {
        printf("Ошибка установки параметров библиотеки: %d\n", result);
        return result;
    }

    // 3. Инициализация ДСЧ
    int flag_init_grn = 1;
    result = cr_init_prnd (
        init_handle,
        "prnd.key",     //имя файла, где хранится ключ ПДСЧ, или NULL, если ключ хранится в ТМ-идентификаторе. Файл должен располагаться на отчуждаемом носителе (дискете или флешке)
        flag_init_grn);    

    if (result != ERR_OK) {
        printf("Ошибка инициализации программного датчика случайных чисел: %d\n", result);
        return result;
    }

    return result;
}

int uninit_bicr() {
    int result = cr_uninit(init_handle);

    if (result != ERR_OK) {
        printf("Ошибка деинициализация библиотеки: %d\n", result);
        return result;
    }

    return result;
}

int export_keys(char* userid, unsigned char* public_key) {
    // 1. Генерация ключевой пары
    int pass_blen = 7;
    H_PKEY pkey_handle;
     
    int result = cr_gen_keypair(
        init_handle, password, &pass_blen, "private.key", &pkey_handle, userid
    );

    if (result != ERR_OK) {
        printf("Ошибка генерации ключевой пары: %d\n", result);
        return 1;
    }

    // Запись пароля в файл
    FILE *file = fopen("password.txt", "w");
    if (file == NULL) {
        cr_pkey_close(pkey_handle);
        perror("Ошибка открытия файла");
        return 1;
    }
    
    fprintf(file, "%s", password);
    fclose(file);

    // 7. Экспортирование открытого ключа
    char pkbuf[256] = {};
    int pkbuf_blen = sizeof(pkbuf);
    result =  cr_pkey_getinfo (
        pkey_handle,
        NULL,
        0,
        pkbuf,
        &pkbuf_blen);

    if (result != ERR_OK)
    {
        printf("Ошибка экспортирования открытого ключа: %d\n", result);
        cr_pkey_close(pkey_handle);
        return 1;
    }

    memcpy(public_key, pkbuf, 32);          // Первые 32 байта
    memcpy(public_key + 32, pkbuf + 64, 32); // Байты 64-95

    // 8. Очистка ресурсов
    cr_pkey_close(pkey_handle);
    
    return result;
}

void reverse_buffer(char* buffer, int length) {
    int i = 0;
    int j = length - 1;
    while (i < j) {
        // Обмен значений между buffer[i] и buffer[j]
        char temp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = temp;
        i++;
        j--;
    }
}

int electronic_signature() {
    // 1. Загрузка из файла закрытого ключа ЭП с паролем
    
    // Открываем файл для чтения 
    /*FILE *file = fopen("password.txt", "r");
    if (file == NULL) {
        printf("Ошибка открытия файла");
        cr_uninit(init_handle);
        return 1;
    }
    
    // Читаем пароль из файла
    if (fgets(password, sizeof(password), file) == NULL) {
        printf("Ошибка чтения из файла");
        fclose(file);
        cr_uninit(init_handle);
        return 1;
    }
    
    fclose(file);*/

    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;

    // 2. Загрузка из файла закрытого ключа ЭП с паролем
    H_USER user_handle;
    int result = cr_read_skey(
        init_handle, password, pass_blen, "private.key", userid, &userid_blen, &user_handle
    );

    if (result != ERR_OK) {
        printf("Ошибка загрузки из файла закрытого ключа ЭП с паролем: %d\n", result);
        return result;
    }

    // 3. Чтениея буфера с сертификатом в формате X.509 из файла
    FILE *file = fopen("tbs.der", "rb");
    if (!file) {
        printf("Ошибка открытия файла tbs.der\n");
        cr_elgkey_close(init_handle, user_handle);
        return 1;
    }

    // Определяем размер буфера с именем
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file); // Используем long для размера файла
    fseek(file, 0, SEEK_SET);

    // Выделяем буфер
    void* dataBuffer = (void*)malloc(file_size);
    if (!dataBuffer) {
        printf("Ошибка выделения памяти\n");
        fclose(file);
        cr_elgkey_close(init_handle, user_handle);
        return 1;
    }

    // Читаем данные
    size_t bytes_read = fread(dataBuffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) { // Сравниваем с учётом типа
        printf("Ошибка чтения файла\n");
        free(dataBuffer);
        cr_elgkey_close(init_handle, user_handle);
        return 1;
    }

    int dataBufferLength = (int)file_size; // Сохраняем реальный размер

    // 4. Формирование ЭП для блока памяти
    char sign[64];
    int sign_blen = sizeof(sign);
    result = cr_sign_buf(
        init_handle,
        user_handle,
        dataBuffer,
        dataBufferLength,
        sign,
        &sign_blen);

    if (result != ERR_OK) {
        printf("Ошибка формирования ЭП для блока памяти: %d\n", result);
        free(dataBuffer);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }  
    
    // Переворачиваем буфер
    reverse_buffer(sign, sign_blen);

    if (sign_blen > 0) {
        FILE *f = fopen("signature.bin", "wb");
        if (f) {
            fwrite(sign, 1, sign_blen, f);
            fclose(f);
        } else {
            printf("Ошибка создания файла\n");
            free(dataBuffer);
            cr_elgkey_close(init_handle, user_handle);
            return 1;
        }
    } else {
        printf("Ошибка генерации подписи\n");
        free(dataBuffer);
        cr_elgkey_close(init_handle, user_handle);
        return 1;
    }

    printf("Подпись сохранена (%d байт)\n", sign_blen);

    free(dataBuffer);
    cr_elgkey_close(init_handle, user_handle);
    printf("ok");

    return 0;
}

