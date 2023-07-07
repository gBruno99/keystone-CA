#include "custom_functions.h"
#include "sm_reference_values.h"
#include "enclave_reference_values.h"

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

int getAttestationPublicKey(mbedtls_x509_csr *csr, unsigned char *pk) {
    mbedtls_x509_crt *cur = &(csr->cert_chain);
    while(cur != NULL) {
        char *id_name = (char *) (cur->subject).val.p;
        size_t id_len = (cur->subject).val.len;
        if(id_len == 16 && my_strncmp(id_name, "Security Monitor", 16) == 0) {
            my_memcpy(pk, mbedtls_pk_ed25519(cur->pk)->pub_key, PUBLIC_KEY_SIZE);
            return 0;
        }
        cur = cur->next;
    }
    return 1;
}

int checkEnclaveTCI(unsigned char *tci, int tci_len) {
    if(tci_len != _reference_tci_enclave_len) return -1;
    return my_memcmp(tci, _reference_tci_enclave, _reference_tci_enclave_len);
}
