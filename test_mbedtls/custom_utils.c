#include "custom_functions.h"
#include "custom_string.h"

// platform_util.c
/*
void mbedtls_platform_zeroize(void *buf, size_t len)
{
    MBEDTLS_INTERNAL_VALIDATE(len == 0 || buf != NULL);
    if (len > 0) {
#if defined(MBEDTLS_PLATFORM_HAS_EXPLICIT_BZERO)
        explicit_bzero(buf, len);
#if defined(HAVE_MEMORY_SANITIZER)
        * You'd think that Msan would recognize explicit_bzero() as
         * equivalent to bzero(), but it actually doesn't on several
         * platforms, including Linux (Ubuntu 20.04).
         * https://github.com/google/sanitizers/issues/1507
         * https://github.com/openssh/openssh-portable/commit/74433a19bb6f4cef607680fa4d1d7d81ca3826aa
         *
        __msan_unpoison(buf, len);
#endif
#elif defined(__STDC_LIB_EXT1__)
        memset_s(buf, len, 0, len);
#elif defined(_WIN32)
        SecureZeroMemory(buf, len);
#else
        memset_func(buf, 0, len);
#endif
    }
}
*/

// oid.c
static const oid_sig_alg_t oid_sig_alg[] =
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
