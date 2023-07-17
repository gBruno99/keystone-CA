#include "custom_functions.h"
#include "sm_reference_value.h"
#include "enclave_reference_value.h"

static int checkWithRefMeasure(const unsigned char* tci, size_t tci_len, const unsigned char* ref_tci, size_t ref_tci_len){
    if(tci_len != ref_tci_len)
        return -1;
    for(int i = 0; i < ref_tci_len; i++){
        if(tci[i] != ref_tci[i])
            return -1;
    }
    return 0;
}

int  checkTCIValue(const custom_x509_name *id, const custom_x509_buf *tci) {

    char *id_name = (char *) id->val.p;
    size_t id_len = id->val.len;
    unsigned char * tci_value = tci->p;
    size_t tci_len = tci->len;

    if(id_len == 12 && custom_strncmp(id_name, "Manufacturer", 12) == 0){
        #if CUSTOM_DEBUG_PRINTS
        printf("Cert is: Manufacturer\n");
        #endif
        return 0;
    }
    if(id_len == 13 && custom_strncmp(id_name, "Root of Trust", 13) == 0){
        #if CUSTOM_DEBUG_PRINTS
        printf("Cert is: Root of Trust\n");
        #endif
        return 0;
    }
    if(id_len == 16 && custom_strncmp(id_name, "Security Monitor", 16) == 0){
        #if CUSTOM_DEBUG_PRINTS
        printf("Cert is: Security Monitor\n");
        #endif
        return checkWithRefMeasure(tci_value, tci_len, sm_reference_value, sm_reference_value_len);
    }
    return -1;
}

int getAttestationPublicKey(custom_x509_csr *csr, unsigned char *pk) {
    custom_x509_crt *cur = &(csr->cert_chain);
    while(cur != NULL) {
        char *id_name = (char *) (cur->subject).val.p;
        size_t id_len = (cur->subject).val.len;
        if(id_len == 16 && custom_strncmp(id_name, "Security Monitor", 16) == 0) {
            custom_memcpy(pk, custom_pk_ed25519(cur->pk)->pub_key, PUBLIC_KEY_SIZE);
            return 0;
        }
        cur = cur->next;
    }
    return 1;
}

int getReferenceTCI(custom_x509_csr *csr, unsigned char *tci) {
    custom_memcpy(tci, enclave_reference_value, enclave_reference_value_len);
    return 0;
}

int checkEnclaveTCI(unsigned char *tci, int tci_len) {
    if(tci_len != enclave_reference_value_len) return -1;
    return custom_memcmp(tci, enclave_reference_value, enclave_reference_value_len);
}
