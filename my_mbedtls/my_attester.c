#include "custom_functions.h"

static const unsigned char _reference_tci_sm[] = {
    0x95, 0xcc, 0x03, 0x03, 0x2d, 0x4c, 0xa5, 0x05, 0x99, 0xc1, 0x61, 0x2d, 0x22, 0xcc, 0x0d, 0x71,
    0x3b, 0xce, 0x3a, 0x90, 0xff, 0x8c, 0x5d, 0x06, 0xa3, 0xd4, 0xfc, 0x7c, 0xd1, 0x36, 0x44, 0x82,
    0xf1, 0xd3, 0x07, 0x19, 0xe7, 0x90, 0x4f, 0xba, 0xa3, 0x22, 0x83, 0x9a, 0xb8, 0x95, 0x8b, 0x86,
    0x6d, 0xc7, 0x05, 0x1d, 0x28, 0x17, 0x09, 0x61, 0xd1, 0x54, 0x02, 0xd3, 0x94, 0x0e, 0xf1, 0x0e
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
