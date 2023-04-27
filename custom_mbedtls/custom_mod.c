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
        //* You'd think that Msan would recognize explicit_bzero() as
        //* equivalent to bzero(), but it actually doesn't on several
        //* platforms, including Linux (Ubuntu 20.04).
        //* https://github.com/google/sanitizers/issues/1507
        //* https://github.com/openssh/openssh-portable/commit/74433a19bb6f4cef607680fa4d1d7d81ca3826aa
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
// asn1parse.c
void mbedtls_asn1_free_named_data_list_mod(int *ne)
{
    *ne = 0;
}

int mbedtls_asn1_get_alg_mod(unsigned char **p,
                             const unsigned char *end,
                             mbedtls_asn1_buf_no_arr *alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        return ret;
    }

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    alg->tag = **p;
    end = *p + len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &alg->len, MBEDTLS_ASN1_OID)) != 0)
    {
        return ret;
    }

    alg->p = *p;
    *p += alg->len;

    if (*p == end)
    {
        // mbedtls_platform_zeroize(params, sizeof(mbedtls_asn1_buf));
        return 0;
    }

    params->tag = **p;
    (*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &params->len)) != 0)
    {
        return ret;
    }

    params->p = *p;
    *p += params->len;

    if (*p != end)
    {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}

// x509.c
int mbedtls_x509_get_alg_mod(unsigned char **p, const unsigned char *end,
                             mbedtls_x509_buf *alg, mbedtls_x509_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg(p, end, alg, params)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_ALG, ret);
    }

    return 0;
}

int mbedtls_x509_get_sig_alg_mod(const mbedtls_x509_buf_crt *sig_oid, const mbedtls_x509_buf *sig_params,
                                 mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                                 void **sig_opts)
{
    // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    *pk_alg = MBEDTLS_PK_ED25519;
    *md_alg = MBEDTLS_MD_SHA384;

    return 0;
}
