#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include <string.h>
// #include "psa/crypto.h"

#define OCALL_STORE_CRT   5
#define OCALL_READ_CRT    6
#define MAC_KEY           0x12121212

int store_crt(unsigned char *crt, int crt_len) {
    unsigned long ret = -1;
    // if(psa_mac_compute((mbedtls_svc_key_id_t)MAC_KEY, PSA_ALG_SHA3_512, crt, crt_len, ))
    ocall(OCALL_STORE_CRT, crt, crt_len, &ret, sizeof(unsigned long));
    if(ret != crt_len)
        return -1;
    return 0;
}

int read_crt(unsigned char *crt, int *crt_len) {
    unsigned long ret = -1;
    unsigned char tmp[1024+sizeof(unsigned long)] = {0};
    ocall(OCALL_READ_CRT, NULL, 0, tmp, 1024+sizeof(unsigned long));
    ret = *((unsigned long *) tmp);
    if(ret == -1)
        return -1;
    *crt_len = ret;
    memcpy(crt, tmp+sizeof(unsigned long), *crt_len);
    return 0;
}