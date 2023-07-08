#include "custom_functions.h"
#include "sha3.h"

const mbedtls_md_info_t mbedtls_keystone_sha3_info = {
    "KEYSTONE_SHA3",
    MBEDTLS_MD_KEYSTONE_SHA3,
    MBEDTLS_HASH_MAX_SIZE,
    200 - 2*MBEDTLS_HASH_MAX_SIZE,
};

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type)
{
    switch (md_type) {
        case MBEDTLS_MD_KEYSTONE_SHA3:
            return &mbedtls_keystone_sha3_info;
        default:
            return NULL;
    }
}

int mbedtls_md(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output)
{
    if (md_info == NULL) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    switch (md_info->type) {
        case MBEDTLS_MD_KEYSTONE_SHA3:
            sha3(input, ilen, output, MBEDTLS_HASH_MAX_SIZE);
            return 0;
        default:
            return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

unsigned char mbedtls_md_get_size(const mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return 0;
    }

    return md_info->size;
}

