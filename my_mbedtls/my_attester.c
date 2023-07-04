#include "custom_functions.h"

static const unsigned char _reference_tci_sm[] = {
    0xe7, 0x92, 0x62, 0x5c, 0xc0, 0x77, 0x9c, 0x1e, 0x94, 0x8a, 0x7e, 0x7b, 0xbb, 0x1e, 0x25, 0xa4, 
    0xe5, 0x90, 0x97, 0xd7, 0x9d, 0x87, 0xd6, 0x37, 0x51, 0x7d, 0xe6, 0x21, 0xfe, 0x32, 0x83, 0xfd, 
    0x5b, 0x9d, 0x0e, 0xd8, 0xbd, 0x05, 0x7f, 0x87, 0x7a, 0x7a, 0xaf, 0x57, 0xf2, 0x2f, 0xf6, 0x03, 
    0x31, 0x3e, 0x46, 0x43, 0xf8, 0xca, 0xf2, 0x4b, 0x04, 0x8a, 0x4b, 0xa0, 0x7d, 0x47, 0xeb, 0x33
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
