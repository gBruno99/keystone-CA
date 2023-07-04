#include "custom_functions.h"

// oid.c
typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    int                 ext_type;
} oid_x509_ext_t;

static const oid_x509_ext_t oid_x509_ext[] =
{
    {
        OID_DESCRIPTOR(MBEDTLS_OID_BASIC_CONSTRAINTS,
                       "id-ce-basicConstraints",
                       "Basic Constraints"),
        MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_KEY_USAGE,            "id-ce-keyUsage",            "Key Usage"),
        MBEDTLS_OID_X509_EXT_KEY_USAGE,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_EXTENDED_KEY_USAGE,
                       "id-ce-extKeyUsage",
                       "Extended Key Usage"),
        MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_SUBJECT_ALT_NAME,
                       "id-ce-subjectAltName",
                       "Subject Alt Name"),
        MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_NS_CERT_TYPE,
                       "id-netscape-certtype",
                       "Netscape Certificate Type"),
        MBEDTLS_OID_X509_EXT_NS_CERT_TYPE,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_CERTIFICATE_POLICIES,
                       "id-ce-certificatePolicies",
                       "Certificate Policies"),
        MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES,
    },
    {
        NULL_OID_DESCRIPTOR,
        0,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_x509_ext_t, x509_ext, oid_x509_ext)
FN_OID_GET_ATTR1(mbedtls_oid_get_x509_ext_type, oid_x509_ext_t, x509_ext, int, ext_type)

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

    lt = gmtime(tt);

    if (lt != NULL) {
        memcpy(tm_buf, lt, sizeof(struct tm));
    }

    return (lt == NULL) ? NULL : tm_buf;
#endif /* _WIN32 && !EFIX64 && !EFI32 */
}
#endif /* MBEDTLS_HAVE_TIME_DATE */
