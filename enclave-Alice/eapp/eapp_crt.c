#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include "app/sealing.h"
#include "eapp/printf.h"
#include "mbedtls/md.h"
#include <string.h>
// #include "psa/crypto.h"

#define OCALL_STORE_CRT   5
#define OCALL_READ_CRT    6
#define HMAC_KEY_SEED     "HMAC_key_seed"

int store_crt(unsigned char *crt, size_t crt_len) {
    unsigned long ret = -1;
    struct sealing_key key_buffer;
    unsigned char tmp[1024];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned long hmac_len = mbedtls_md_get_size(md_info);
    if((ret = get_sealing_key(&key_buffer, sizeof(key_buffer), (void*)HMAC_KEY_SEED, strlen(HMAC_KEY_SEED))) != 0) {
        return -2;
    }
    /*                  
    custom_printf("HMAC key: 0x");
    for(int i = 0; i < SEALING_KEY_SIZE; i++)
        custom_printf("%02x", (key_buffer.key)[i]);
    custom_printf("\n");
    */
    memcpy(tmp, crt, crt_len);
    if((ret = mbedtls_md_hmac(md_info, key_buffer.key, SEALING_KEY_SIZE, crt, crt_len, tmp+crt_len)) != 0) {
        return -3;
    }
    ocall(OCALL_STORE_CRT, tmp, crt_len+hmac_len, &ret, sizeof(unsigned long));
    if(ret != (crt_len+hmac_len))
        return -1;
    return 0;
}

int read_crt(unsigned char *crt, size_t *crt_len) {
    unsigned long ret = -1;
    unsigned long len = 0;
    unsigned char tmp[1024+sizeof(unsigned long)] = {0};
    unsigned char hmac[512];
    unsigned long hmac_len = 0;
    struct sealing_key key_buffer;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ocall(OCALL_READ_CRT, NULL, 0, tmp, 1024+sizeof(unsigned long));
    len = *((unsigned long *) tmp);
    if(len == -1)
        return -1;
    if((ret = get_sealing_key(&key_buffer, sizeof(key_buffer), (void*)HMAC_KEY_SEED, strlen(HMAC_KEY_SEED))) != 0) {
        return -2;
    }
    hmac_len = mbedtls_md_get_size(md_info);
    *crt_len = len-hmac_len;
    // tmp[200] = '\x00'; // certificate is modified
    // tmp[440] = '\x00'; // HMAC is modified
    if((ret = mbedtls_md_hmac(md_info, key_buffer.key, SEALING_KEY_SIZE, tmp+sizeof(unsigned long), *crt_len, hmac)) != 0) {
        return -3;
    }
    if(memcmp(hmac, tmp+sizeof(unsigned long)+(*crt_len), hmac_len)!=0) {
        return -4;
    }
    memcpy(crt, tmp+sizeof(unsigned long), *crt_len);
    return 0;
}