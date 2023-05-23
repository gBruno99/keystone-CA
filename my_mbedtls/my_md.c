#include "custom_functions.h"

const mbedtls_md_info_t mbedtls_md5_info = {
    "MD5",
    MBEDTLS_MD_MD5,
    16,
    64,
};

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type)
{
    switch (md_type) {
#if defined(MBEDTLS_MD_CAN_MD5)
        case MBEDTLS_MD_MD5:
            return &mbedtls_md5_info;
#endif
#if defined(MBEDTLS_MD_CAN_RIPEMD160)
        case MBEDTLS_MD_RIPEMD160:
            return &mbedtls_ripemd160_info;
#endif
#if defined(MBEDTLS_MD_CAN_SHA1)
        case MBEDTLS_MD_SHA1:
            return &mbedtls_sha1_info;
#endif
#if defined(MBEDTLS_MD_CAN_SHA224)
        case MBEDTLS_MD_SHA224:
            return &mbedtls_sha224_info;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_MD_SHA256:
            return &mbedtls_sha256_info;
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_MD_SHA384:
            return &mbedtls_sha384_info;
#endif
#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_MD_SHA512:
            return &mbedtls_sha512_info;
#endif
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

#if defined(MBEDTLS_MD_SOME_PSA)
    if (md_can_use_psa(md_info)) {
        size_t size = md_info->size;
        psa_status_t status = psa_hash_compute(psa_alg_of_md(md_info),
                                               input, ilen,
                                               output, size, &size);
        return mbedtls_md_error_from_psa(status);
    }
#endif

    switch (md_info->type) {
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_MD_MD5:
            return mbedtls_md5(input, ilen, output);
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case MBEDTLS_MD_RIPEMD160:
            return mbedtls_ripemd160(input, ilen, output);
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_MD_SHA1:
            return mbedtls_sha1(input, ilen, output);
#endif
#if defined(MBEDTLS_SHA224_C)
        case MBEDTLS_MD_SHA224:
            return mbedtls_sha256(input, ilen, output, 1);
#endif
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            return mbedtls_sha256(input, ilen, output, 0);
#endif
#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            return mbedtls_sha512(input, ilen, output, 1);
#endif
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            return mbedtls_sha512(input, ilen, output, 0);
#endif
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

