#define UNIX
#include "bcry.h"
#include "errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

H_INIT init_handle;
char password[7] = {0}; // 6 символов + '\0'

int init_bicr() {
    openlog("Bicry", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_DEBUG, "Initializing BICRY library");

    int result = cr_load_bicr_dll("");
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to load BICRY DLL: error %d", result);
        return result;
    }

    int init_mode = 0;
    result = cr_init(0, "", "", "", NULL, NULL, &init_mode, &init_handle);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Library initialization failed: error %d", result);
        return result;
    }

    int flag_init_grn = 1;
    result = cr_init_prnd(init_handle, "prnd.key", flag_init_grn);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "PRNG initialization failed: error %d", result);
        return result;
    }

    syslog(LOG_INFO, "BICRY library initialized successfully");
    return result;
}

int uninit_bicr() {
    syslog(LOG_INFO, "Uninitializing BICRY library");
    int result = cr_uninit(init_handle);
    
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Uninitialization failed: error %d", result);
    } else {
        syslog(LOG_INFO, "BICRY library uninitialized successfully");
    }
    
    closelog();
    return result;
}

int generate_temp_keypair(int param, char* userid, unsigned char* pw, unsigned char* private_key, unsigned char* public_key) {
    syslog(LOG_INFO, "Generating temp keypair for user: %s, param: %d", userid, param);

    int option = 1;
    int result = cr_set_param(init_handle, option, param);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to set crypto parameter: error %d", result);
        return result;
    }

    int pass_blen = 7;
    H_PKEY pkey_handle;
    result = cr_gen_keypair(init_handle, password, &pass_blen, 
                           "temp_private.key", &pkey_handle, userid);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Keypair generation failed: error %d", result);
        return result;
    }

    char pkbuf[256] = {};
    int pkbuf_blen = sizeof(pkbuf);
    result = cr_pkey_getinfo(pkey_handle, NULL, 0, pkbuf, &pkbuf_blen);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to export public key: error %d", result);
        cr_pkey_close(pkey_handle);
        return result;
    }

    memcpy(pw, password, 6);
    pw[6] = '\0';

    FILE* file = fopen("temp_private.key", "rb");
    if (!file) {
        syslog(LOG_ERR, "Failed to open temp_private.key file");
        return ERR_OPEN_FILE;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size > 0) {
        size_t read = fread(private_key, 1, file_size, file);
        if (read != (size_t)file_size) {
            syslog(LOG_ERR, "Failed to read temp_private key: expected %ld bytes, got %zu", 
                  file_size, read);
            fclose(file);
            return ERR_READ_FILE;
        }
        syslog(LOG_DEBUG, "Read %ld bytes from temp_private.key", file_size);
    }
    fclose(file);    

    if (param == 49 || param == 50 || param == 51) {
        memcpy(public_key, pkbuf, 128);
        syslog(LOG_DEBUG, "Generated 128-byte public key");
    } else {
        memcpy(public_key, pkbuf, 32);
        memcpy(public_key + 32, pkbuf + 64, 32);
        syslog(LOG_DEBUG, "Generated 64-byte public key");
    }

    cr_pkey_close(pkey_handle);
    syslog(LOG_INFO, "Temp keypair generated successfully");
    return result;
}

void reverse_buffer(char* buffer, int length) {
    for (int i = 0, j = length - 1; i < j; i++, j--) {
        char temp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = temp;
    }
}

int temp_electronic_signature(unsigned char* es, unsigned char* cert_data, 
                         size_t cert_data_len, int param) {
    syslog(LOG_INFO, "Creating temp electronic signature for %zu bytes of data", cert_data_len);

    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;
    H_USER user_handle;
    
    int result = cr_read_skey(init_handle, password, pass_blen, "temp_private.key", 
                             userid, &userid_blen, &user_handle);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to load temp private key for signing: error %d", result);
        return result;
    }

    int sign_size = (param >= 49 && param <= 51) ? 128 : 64;
    char sign[sign_size];
    int sign_blen = sizeof(sign);
    
    result = cr_sign_buf(init_handle, user_handle, cert_data, cert_data_len, 
                        sign, &sign_blen);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Temp signature creation failed: error %d", result);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }

    reverse_buffer(sign, sign_blen);
    memcpy(es, sign, sign_size);
    syslog(LOG_DEBUG, "Temp signature created successfully (%d bytes)", sign_blen);

    cr_elgkey_close(init_handle, user_handle);
    return 0;
}

int change_active_cert(int param, unsigned char* pw, unsigned char* private_key, unsigned char* public_key, size_t len_public_key, bool* check_param_flag, bool* check_openkey_flag) {
    *check_param_flag = false;
    *check_openkey_flag = false;
    // 1. Сохранение ключевой информации в файл private.key
    FILE *file = fopen("private.key", "wb");
    if (!file) {
        syslog(LOG_ERR, "Failed to open private.key for writing");
        return ERR_OPEN_FILE;
    }

    size_t private_key_len = 69;
    size_t written = fwrite(private_key, 1, private_key_len, file);
    if (written != private_key_len) {
        syslog(LOG_ERR, "Failed to write private key completely");
        fclose(file);
        return ERR_OPEN_FILE;
    }

    fclose(file);
    
    // 2. Сохранение пароля в ОП
    memcpy(password, pw, 6);
    //password[6] = '\0';  // Явно добавляем нуль-терминатор

    syslog(LOG_DEBUG, "Checking parameter: %d", param);

    int pass_blen = 6;
    char userid[33];
    int userid_blen = 33;
    H_USER user_handle;

    // 3. Загрузка из файла закрытого ключа ЭП с паролем
    int result = cr_read_skey(init_handle, password, pass_blen, "private.key", 
                             userid, &userid_blen, &user_handle);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to load private key: error %d", result);
        return result;
    }

    // 4. Получение параметров библиотеки
    int option = 1;
    int value;
    result = cr_get_param(user_handle, option, &value);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to get crypto parameter: error %d", result);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }

    if (value == param) {
        *check_param_flag = true;
        syslog(LOG_INFO, "Parameter validated: %d", param);
    } else {
        syslog(LOG_WARNING, "Invalid parameter: expected %d, got %d", param, value);
        cr_elgkey_close(init_handle, user_handle);
        return ERR_OK;
    }

    // 5. Генерация открытого ключа
    H_PKEY pkey_handle;
    result = cr_gen_pubkey(init_handle, user_handle, &pkey_handle);
    if (result != ERR_OK) {
        syslog(LOG_ERR, "Public key generation failed: error %d", result);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }

    // 6. Экспортирование открытого ключа
    char pkbuf[256] = {};
    int pkbuf_blen = sizeof(pkbuf);
    result =  cr_pkey_getinfo (
        pkey_handle,
        NULL,
        0,
        pkbuf,
        &pkbuf_blen);

    if (result != ERR_OK) {
        syslog(LOG_ERR, "Failed to export public key for comparison: error %d", result);
        cr_pkey_close(pkey_handle);
        cr_elgkey_close(init_handle, user_handle);
        return result;
    }
    
    int match = 0;
    if (len_public_key == 128) {
        match = memcmp(public_key, pkbuf, 128) == 0;
    } else {
        match = (memcmp(public_key, pkbuf, 32) == 0) && 
                (memcmp(public_key + 32, pkbuf + 64, 32) == 0);
    }

    if (!match) {
        syslog(LOG_WARNING, "Key mismatch detected");
    } else {
        syslog(LOG_INFO, "Keys match");
        *check_openkey_flag = true;
    }

    cr_pkey_close(pkey_handle);
    cr_elgkey_close(init_handle, user_handle);
    return result;
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