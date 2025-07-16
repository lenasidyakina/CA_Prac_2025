#define UNIX
#include "bcry.h"
#include "errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


H_INIT init_handle;
char password[7] = {0}; // 6 символов + '\0'

int init_bicr() {
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

    // 2. Инициализация ДСЧ
    int flag_init_grn = 1;
    result = cr_init_prnd (
        init_handle,
        "prnd.key",     //имя файла, где хранится ключ ПДСЧ, или NULL, если ключ хранится в ТМ-идентификаторе. Файл должен располагаться на отчуждаемом носителе (дискете или флешке)
        flag_init_grn);    

    if (result != ERR_OK) {
        printf("Ошибка инициализации программного датчика случайных чисел: %d\n", result);
        return result;
    }

    FILE* file = fopen("password.txt", "r");
    if (file) {
        if (fgets(password, sizeof(password), file) == NULL) {
            memset(password, 0, sizeof(password));
        }
        fclose(file);
    }    

    return result;
}

int check_param(int param, bool* check_flag) {
    *check_flag = false;

    // 1. Загрузка из файла закрытого ключа ЭП с паролем
    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;

    H_USER user_handle;
    int result = cr_read_skey(
        init_handle, password, pass_blen, "private.key", userid, &userid_blen, &user_handle
    );

    if (result != ERR_OK) {
        printf("Ошибка загрузки из файла закрытого ключа ЭП с паролем: %d\n", result);
        return result;
    }

    // 3. Получаем параметр криптографиеского алгоритма закрытого ключа
    int option = 1;
    int value;
    result = cr_get_param (
        user_handle,
        option,
        &value);

    if (result != ERR_OK) {
        printf("Ошибка получения параметров библиотеки: %d\n", result);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }
    printf("value = %d, param = %d\n", value, param);
    if (value == param)
        *check_flag = true;
        
    cr_elgkey_close(init_handle, user_handle);

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

int generate_keypair(int param, char* userid, unsigned char* public_key) {
    // 1. Установка параметров библиотеки
    int option = 1;
    int result = cr_set_param (
        init_handle,            //дескриптор H_INIT, возвращенный функцией cr_init() или дескриптор H_USER, возвращенный функцией cr_read_skey() или дескриптор H_PKEY, возвращенный функцией cr_pkey_load()
        option,             //номер опции, принимает значение 1
        param);             //значение опции option. для опции option=1: установка параметров криптографических алгоритмов – см. Приложение №3

    if (result != ERR_OK) {
        printf("Ошибка установки параметров библиотеки: %d\n", result);
        return result;
    }

    // 2. Генерация ключевой пары
    int pass_blen = 7;
    H_PKEY pkey_handle;
     
    result = cr_gen_keypair(
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

    // 3. Экспортирование открытого ключа
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

    if (param == 49 || param == 50 || param == 51) {
        memcpy(public_key, pkbuf, 128);
    }
    else {
        memcpy(public_key, pkbuf, 32);
        memcpy(public_key + 32, pkbuf + 64, 32);
    }

    // 4. Очистка ресурсов
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

int electronic_signature(unsigned char* es, unsigned char* cert_data, size_t cert_data_len, int param) {
    // 1. Загрузка из файла закрытого ключа ЭП с паролем
    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;

    H_USER user_handle;
    int result = cr_read_skey(
        init_handle, password, pass_blen, "private.key", userid, &userid_blen, &user_handle
    );

    if (result != ERR_OK) {
        printf("Ошибка загрузки из файла закрытого ключа ЭП с паролем: %d\n", result);
        return result;
    }

    // 2. Используем переданный буфер с сертификатом
    void* dataBuffer = cert_data;
    int dataBufferLength = (int)cert_data_len;

    // 3. Формирование ЭП для блока памяти
    int sign_size = (param >= 49 && param <= 51) ? 128 : 64;
    char sign[sign_size];
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
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }  
    
    // 4. Переворачиваем буфер
    reverse_buffer(sign, sign_blen);

    memcpy(es, sign, sign_size);    //sign_size

    cr_elgkey_close(init_handle, user_handle);

    return 0;
}

int get_elgkey_with_password(unsigned char* pw, unsigned char* private_key) {

    FILE* file = fopen("private.key", "rb");
    if (!file) {
        printf("Failed to open private.key file\n");
        return ERR_OPEN_FILE;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    
    size_t read = fread(private_key, 1, file_size, file);
    fclose(file);
    
    if (read != (size_t)file_size) {
        printf("Failed to read private key\n");
        return ERR_OPEN_FILE;
    }
    
    memcpy(pw, password, 6);
    pw[6] = '\0';  // Явно добавляем нуль-терминатор

    return 0;
}

int compare_keys(unsigned char* public_key, size_t len_public_key) {
    // 1. Загрузка из файла закрытого ключа ЭП с паролем
    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;

    H_USER user_handle;
    int result = cr_read_skey(
        init_handle, password, pass_blen, "private.key", userid, &userid_blen, &user_handle
    );

    if (result != ERR_OK) {
        printf("Ошибка загрузки из файла закрытого ключа ЭП с паролем: %d\n", result);
        return result;
    }

    // 2. Генерация открытого ключа
    H_PKEY pkey_handle;
    result = cr_gen_pubkey( 
        init_handle,
        user_handle,
        &pkey_handle
    );

     if (result != ERR_OK) {
        printf("Ошибка генерации открытого ключа: %d\n", result);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }

    // 3. Экспортирование открытого ключа
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
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }

    if (len_public_key == 128) {
        if (memcmp(public_key, pkbuf, len_public_key) != 0) {
            printf("Открытый ключ не соответсвует закрытому\n");
            cr_pkey_close(pkey_handle);
            cr_elgkey_close(init_handle, user_handle);
            return 1;  // Не совпали
        }
    }
    else {
        // Сравнение первых 32 байт
        if (memcmp(public_key, pkbuf, 32) != 0) {
            printf("Открытый ключ не соответсвует закрытому\n");
            cr_pkey_close(pkey_handle);
            cr_elgkey_close(init_handle, user_handle);
            return 1;  // Не совпали
        }

        // Сравнение вторых 32 байт
        if (memcmp(public_key + 32, pkbuf + 64, 32) != 0) {
            printf("Открытый ключ не соответсвует закрытому\n");
            cr_pkey_close(pkey_handle);
            cr_elgkey_close(init_handle, user_handle);
            return 1;  // Не совпали
    }
    }

    cr_pkey_close(pkey_handle);
    cr_elgkey_close(init_handle, user_handle);
    return 0;  // Ключи совпали
}