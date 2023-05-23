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
            MBEDTLS_MD_KEYSTONE_SHA3,
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
    if (md_type == MBEDTLS_MD_KEYSTONE_SHA3) // MBEDTLS_MD_SHA512 ??
        return MBEDTLS_HASH_MAX_SIZE;
    return 0;
}

// platform_util.c

#if defined(MBEDTLS_HAVE_TIME_DATE)
struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf)
{
#if defined(_WIN32) && !defined(PLATFORM_UTIL_USE_GMTIME)
#if defined(__STDC_LIB_EXT1__)
    return (gmtime_s(tt, tm_buf) == 0) ? NULL : tm_buf;
#else
    /* MSVC and mingw64 argument order and return value are inconsistent with the C11 standard */
    return (gmtime_s(tm_buf, tt) == 0) ? tm_buf : NULL;
#endif
#elif !defined(PLATFORM_UTIL_USE_GMTIME)
    return gmtime_r(tt, tm_buf);
#else
    struct tm *lt;

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_gmtime_mutex) != 0) {
        return NULL;
    }
#endif /* MBEDTLS_THREADING_C */

    lt = gmtime(tt);

    if (lt != NULL) {
        memcpy(tm_buf, lt, sizeof(struct tm));
    }

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_gmtime_mutex) != 0) {
        return NULL;
    }
#endif /* MBEDTLS_THREADING_C */

    return (lt == NULL) ? NULL : tm_buf;
#endif /* _WIN32 && !EFIX64 && !EFI32 */
}
#endif /* MBEDTLS_HAVE_TIME_DATE */
