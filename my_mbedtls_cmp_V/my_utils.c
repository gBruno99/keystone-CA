// oid.c
/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s) s, MBEDTLS_OID_SIZE(s)

#define OID_DESCRIPTOR(s, name, description) \
    {                                        \
        ADD_LEN(s), name, description        \
    }

/*
 * Macro to generate a function for retrieving the OID based on two
 * attributes from a mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1, \
                                ATTR2_TYPE, ATTR2)                        \
    int FN_NAME(ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid,     \
                size_t *olen)                                             \
    {                                                                     \
        const TYPE_T *cur = (LIST);                                       \
        while (cur->descriptor.asn1 != NULL)                              \
        {                                                                 \
            if (cur->ATTR1 == (ATTR1) && cur->ATTR2 == (ATTR2))           \
            {                                                             \
                *oid = cur->descriptor.asn1;                              \
                *olen = cur->descriptor.asn1_len;                         \
                return 0;                                                 \
            }                                                             \
            cur++;                                                        \
        }                                                                 \
        return MBEDTLS_ERR_OID_NOT_FOUND;                                 \
    }

/*
 * For SignatureAlgorithmIdentifier
 */
typedef struct
{
    mbedtls_oid_descriptor_t descriptor;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_type_t pk_alg;
} oid_sig_alg_t;

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
unsigned char mbedtls_hash_info_get_size(mbedtls_md_type_t md_type)
{
    if (md_type == MBEDTLS_MD_SHA3)
        return MBEDTLS_HASH_MAX_SIZE;
    return 0;
}