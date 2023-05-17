#include "custom_functions.h"

// oid.c
const oid_sig_alg_t oid_sig_alg[] = // new_impl
    {
        {
            OID_DESCRIPTOR(MBEDTLS_OID_PKCS1_MD5, "md5WithRSAEncryption", "RSA with MD5"),
            MBEDTLS_MD_MD5,
            MBEDTLS_PK_RSA,
        },
        {
            OID_DESCRIPTOR(MBEDTLS_OID_PKCS1_SHA224, "sha224WithRSAEncryption", "RSA with SHA-224"),
            MBEDTLS_MD_SHA224,
            MBEDTLS_PK_RSA,
        },
        {
            OID_DESCRIPTOR(MBEDTLS_OID_ECDSA_SHA1, "ecdsa-with-SHA1", "ECDSA with SHA1"),
            MBEDTLS_MD_SHA1,
            MBEDTLS_PK_ECDSA,
        },
        {
            OID_DESCRIPTOR("\x2B\x65\x70", "ed25519", "ed25519 with sha3"),
            MBEDTLS_MD_SHA512,
            MBEDTLS_PK_ED25519,
        },
};

FN_OID_GET_OID_BY_ATTR2(mbedtls_oid_get_oid_by_sig_alg,
                        oid_sig_alg_t,
                        oid_sig_alg,
                        mbedtls_pk_type_t,
                        pk_alg,
                        mbedtls_md_type_t,
                        md_alg)

// hash_info.c
unsigned char mbedtls_hash_info_get_size(mbedtls_md_type_t md_type) // new_impl
{
    if (md_type == MBEDTLS_MD_SHA3) // MBEDTLS_MD_SHA512 ??
        return MBEDTLS_HASH_MAX_SIZE;
    return 0;
}
