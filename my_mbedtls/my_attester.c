#include "custom_functions.h"

static const unsigned char _reference_tci_sm[] = {
    0x07, 0x93, 0xea, 0xbb, 0x15, 0xcf, 0x1d, 0xdd, 0xcd, 0xdf, 0x4b, 0x50, 0xe6, 0x97, 0x7e, 0x3b, 
    0x24, 0xa1, 0xc8, 0xca, 0x5d, 0xf0, 0x3a, 0x69, 0xe6, 0x77, 0x47, 0x1a, 0x30, 0x5d, 0x2c, 0x09, 
    0x21, 0x34, 0xcb, 0xec, 0x96, 0x6e, 0x98, 0x08, 0x70, 0xd4, 0x6f, 0xdc, 0x19, 0x50, 0x8c, 0x7f, 
    0x5f, 0x1d, 0x25, 0x64, 0xdb, 0xdd, 0x57, 0x89, 0x14, 0xa8, 0xcf, 0x48, 0xd9, 0x27, 0x59, 0xf5
};

static const size_t _reference_tci_sm_len = 64;

static int checkWithRefMeasure(const unsigned char* tci, size_t tci_len, const unsigned char* ref_tci, size_t ref_tci_len){
    if(tci_len != ref_tci_len)
        return -1;
    for(int i = 0; i < ref_tci_len; i++){
        if(tci[i] != ref_tci[i])
            return -1;
    }
    return 0;
}

int  checkTCIValue(const mbedtls_x509_name *id, const mbedtls_x509_buf *tci) {

    char *id_name = (char *) id->val.p;
    size_t id_len = id->val.len;
    unsigned char * tci_value = tci->p;
    size_t tci_len = tci->len;

    if(id_len == 12 && my_strncmp(id_name, "Manufacturer", 12) == 0){
        my_printf("Cert is: Manufacturer\n");
        return 0;
    }
    if(id_len == 13 && my_strncmp(id_name, "Root of Trust", 13) == 0){
        my_printf("Cert is: Root of Trust\n");
        return 0;
    }
    if(id_len == 16 && my_strncmp(id_name, "Security Monitor", 16) == 0){
        my_printf("Cert is: Security Monitor\n");
        return checkWithRefMeasure(tci_value, tci_len, _reference_tci_sm, _reference_tci_sm_len);
    }
    return -1;
}
