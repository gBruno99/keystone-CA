#include "custom_functions.h"
#include "custom_string.h"

// x509_create.c
const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++)
    {
        if (cur->name_len == name_len &&
            strncmp(cur->name, name, name_len) == 0)
        {
            break;
        }
    }

    if (cur->name == NULL)
    {
        return NULL;
    }

    return cur;
}
/*
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name)
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen(s);
    const char *oid = NULL;
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_tag = 1;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    // Clear existing chain if present
    mbedtls_asn1_free_named_data_list(head);

    while (c <= end) {
        if (in_tag && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, c - s)) == NULL) {
                ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end) {
            c++;

            // Check for valid escaped characters
            if (c == end || *c != ',') {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        } else if (!in_tag && (*c == ',' || c == end)) {
            mbedtls_asn1_named_data *cur =
                mbedtls_asn1_store_named_data(head, oid, strlen(oid),
                                              (unsigned char *) data,
                                              d - data);

            if (cur == NULL) {
                return MBEDTLS_ERR_X509_ALLOC_FAILED;
            }

            // set tagType
            cur->val.tag = attr_descr->default_tag;

            while (c < end && *(c + 1) == ' ') {
                c++;
            }

            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1) {
            *(d++) = *c;

            if (d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE) {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return ret;
}
*/

int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p < start || (size_t)(*p - start) < size)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    memcpy(*p, sig, len);

    if (*p - start < 1)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));

    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(p, start, oid,
                                                                      oid_len, 0));

    return (int)len;
}

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur = first;

    while (cur != NULL)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_name(p, start, cur));
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int x509_write_name(unsigned char **p,
                    unsigned char *start,
                    mbedtls_asn1_named_data *cur_name)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid = (const char *)cur_name->oid.p;
    size_t oid_len = cur_name->oid.len;
    const unsigned char *name = cur_name->val.p;
    size_t name_len = cur_name->val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name->val.tag,
                                                               (const char *)name,
                                                               name_len));
    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid,
                                                     oid_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                         MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                         MBEDTLS_ASN1_SET));

    return (int)len;
}

// x509write_crt.c
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_x509write_cert));

    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
}
/*
int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx,
                                           const char *subject_name)
{
    return mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}
*/
/*
int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx,
                                        const char *issuer_name)
{
  return mbedtls_x509_string_to_names(&ctx->issuer, issuer_name);
}
*/

void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx,
                                           mbedtls_pk_context *key)
{
    ctx->subject_key = key;
}

void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx,
                                          mbedtls_pk_context *key)
{
    ctx->issuer_key = key;
}

int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx,
                                       const char *not_before,
                                       const char *not_after)
{
    if (strlen(not_before) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen(not_after) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    strncpy(ctx->not_before, not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    strncpy(ctx->not_after, not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t hash_length = 0;
    unsigned char hash[MBEDTLS_HASH_MAX_SIZE];
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t psa_algorithm;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed at the end of the target buffer
     */
    c = buf + size;

    /* Signature algorithm needed in TBS, and later for actual signature */

    /* There's no direct way of extracting a signature algorithm
     * (represented as an element of mbedtls_pk_type_t) from a PK instance. */
    if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_RSA))
    {
        pk_alg = MBEDTLS_PK_RSA;
    }
    else if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_ECDSA))
    {
        pk_alg = MBEDTLS_PK_ECDSA;
    }
    else
    {
        return MBEDTLS_ERR_X509_INVALID_ALG;
    }

    if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0)
    {
        return ret;
    }

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if (ctx->version == MBEDTLS_X509_CRT_VERSION_3)
    {
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_x509_write_extensions(&c,
                                                           buf, ctx->extensions));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                        MBEDTLS_ASN1_SEQUENCE));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                        MBEDTLS_ASN1_CONSTRUCTED | 3));
    }

    /*
     *  SubjectPublicKeyInfo
     */
    MBEDTLS_ASN1_CHK_ADD(pub_len,
                         mbedtls_pk_write_pubkey_der(ctx->subject_key,
                                                     buf, c - buf));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names(&c, buf,
                                                  ctx->subject));

    /*
     *  Validity ::= SEQUENCE {
     *       notBefore      Time,
     *       notAfter       Time }
     */
    sub_len = 0;

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_after,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_before,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf,
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE));

    /*
     *  Issuer  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf,
                                                       ctx->issuer));

    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(&c, buf,
                                                                 sig_oid, strlen(sig_oid), 0));

    /*
     *  Serial   ::=  INTEGER
     *
     * Written data is:
     * - "ctx->serial_len" bytes for the raw serial buffer
     *   - if MSb of "serial" is 1, then prepend an extra 0x00 byte
     * - 1 byte for the length
     * - 1 byte for the TAG
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf,
                                                            ctx->serial, ctx->serial_len));
    if (*c & 0x80)
    {
        if (c - buf < 1)
        {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        *(--c) = 0x0;
        len++;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len + 1));
    }
    else
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_INTEGER));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */
    if (ctx->version != MBEDTLS_X509_CRT_VERSION_1)
    {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_int(&c, buf, ctx->version));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_len(&c, buf, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                        MBEDTLS_ASN1_CONSTRUCTED | 0));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /*
     * Make signature
     */

    /* Compute hash of CRT. */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_algorithm = mbedtls_hash_info_psa_from_md(ctx->md_alg);

    status = psa_hash_compute(psa_algorithm,
                              c,
                              len,
                              hash,
                              sizeof(hash),
                              &hash_length);
    if (status != PSA_SUCCESS)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else
    if ((ret = mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), c,
                          len, hash)) != 0)
    {
        return ret;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if ((ret = mbedtls_pk_sign(ctx->issuer_key, ctx->md_alg,
                               hash, hash_length, sig, sizeof(sig), &sig_len,
                               f_rng, p_rng)) != 0)
    {
        return ret;
    }

    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    memmove(buf, c, len);
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, c,
                                                                 sig_oid, sig_oid_len, sig,
                                                                 sig_len));

    /*
     * Memory layout after this step:
     *
     * buf       c=buf+len                c2            buf+size
     * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
     */

    /* Move raw CRT to just before the signature. */
    c = c2 - len;
    memmove(c, buf, len);

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                         MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int x509_write_time(unsigned char **p, unsigned char *start,
                    const char *t, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    /*
     * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if (t[0] < '2' || (t[0] == '2' && t[1] == '0' && t[2] < '5'))
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *)t + 2,
                                                                size - 2));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_UTC_TIME));
    }
    else
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *)t,
                                                                size));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_GENERALIZED_TIME));
    }

    return (int)len;
}

int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len)
{
    if (serial_len > MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ctx->serial_len = serial_len;
    memcpy(ctx->serial, serial, serial_len);

    return 0;
}

void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx,
                                      mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

// x509_crt.c
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 1, NULL, NULL);
}

static int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain,
                                               const unsigned char *buf,
                                               size_t buflen,
                                               int make_copy,
                                               mbedtls_x509_crt_ext_cb_t cb,
                                               void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if (crt == NULL || buf == NULL)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    while (crt->version != 0 && crt->next != NULL)
    {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if (crt->version != 0 && crt->next == NULL)
    {
        crt->next = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));

        if (crt->next == NULL)
        {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        prev = crt;
        mbedtls_x509_crt_init(crt->next);
        crt = crt->next;
    }

    ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx);
    if (ret != 0)
    {
        if (prev)
        {
            prev->next = NULL;
        }

        if (crt != chain)
        {
            mbedtls_free(crt);
        }

        return ret;
    }

    return 0;
}

void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
    memset(crt, 0, sizeof(mbedtls_x509_crt));
}

int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                            const unsigned char *buf,
                            size_t buflen,
                            int make_copy,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end, *crt_end;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;

    memset(&sig_params1, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_params2, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_oid2, 0, sizeof(mbedtls_x509_buf));

    /*
     * Check for valid input
     */
    if (crt == NULL || buf == NULL)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    /* Use the original buffer until we figure out actual length. */
    p = (unsigned char *)buf;
    len = buflen;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    end = crt_end = p + len;
    crt->raw.len = crt_end - buf;
    if (make_copy != 0)
    {
        /* Create and populate a new buffer for the raw field. */
        crt->raw.p = p = mbedtls_calloc(1, crt->raw.len);
        if (crt->raw.p == NULL)
        {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        memcpy(crt->raw.p, buf, crt->raw.len);
        crt->own_buffer = 1;

        p += crt->raw.len - len;
        end = crt_end = p + len;
    }
    else
    {
        crt->raw.p = (unsigned char *)buf;
        crt->own_buffer = 0;
    }

    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */
    if ((ret = x509_get_version(&p, end, &crt->version)) != 0 ||
        (ret = mbedtls_x509_get_serial(&p, end, &crt->serial)) != 0 ||
        (ret = mbedtls_x509_get_alg(&p, end, &crt->sig_oid,
                                    &sig_params1)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->version < 0 || crt->version > 2)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }

    crt->version++;

    if ((ret = mbedtls_x509_get_sig_alg(&crt->sig_oid, &sig_params1,
                                        &crt->sig_md, &crt->sig_pk,
                                        &crt->sig_opts)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    /*
    if ((ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    */
    crt->issuer_raw.len = p - crt->issuer_raw.p;

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if ((ret = x509_get_dates(&p, end, &crt->valid_from,
                              &crt->valid_to)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    /*
    if (len && (ret = mbedtls_x509_get_name(&p, p + len, &crt->subject)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    */
    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo
     */
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->pk_raw.len = p - crt->pk_raw.p;

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
    if (crt->version == 2 || crt->version == 3)
    {
        ret = x509_get_uid(&p, end, &crt->issuer_id, 1);
        if (ret != 0)
        {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 2 || crt->version == 3)
    {
        ret = x509_get_uid(&p, end, &crt->subject_id, 2);
        if (ret != 0)
        {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 3)
    {
        ret = x509_get_crt_ext(&p, end, crt, cb, p_ctx);
        if (ret != 0)
        {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (p != end)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    end = crt_end;

    /*
     *  }
     *  -- end of TBSCertificate
     *
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if ((ret = mbedtls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->sig_oid.len != sig_oid2.len ||
        memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 ||
        sig_params1.tag != sig_params2.tag ||
        sig_params1.len != sig_params2.len ||
        (sig_params1.len != 0 &&
         memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0))
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_SIG_MISMATCH;
    }

    if ((ret = mbedtls_x509_get_sig(&p, end, &crt->sig)) != 0)
    {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (p != end)
    {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}
/*
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt)
{
    mbedtls_x509_crt *cert_cur = crt;
    mbedtls_x509_crt *cert_prv;

    while (cert_cur != NULL) {
        mbedtls_pk_free(&cert_cur->pk);

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free(cert_cur->sig_opts);
#endif

        mbedtls_asn1_free_named_data_list_shallow(cert_cur->issuer.next);
        mbedtls_asn1_free_named_data_list_shallow(cert_cur->subject.next);
        mbedtls_asn1_sequence_free(cert_cur->ext_key_usage.next);
        mbedtls_asn1_sequence_free(cert_cur->subject_alt_names.next);
        mbedtls_asn1_sequence_free(cert_cur->certificate_policies.next);

        if (cert_cur->raw.p != NULL && cert_cur->own_buffer) {
            mbedtls_platform_zeroize(cert_cur->raw.p, cert_cur->raw.len);
            mbedtls_free(cert_cur->raw.p);
        }

        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        mbedtls_platform_zeroize(cert_prv, sizeof(mbedtls_x509_crt));
        if (cert_prv != crt) {
            mbedtls_free(cert_prv);
        }
    }
}
*/

int x509_get_version(unsigned char **p,
                     const unsigned char *end,
                     int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                        0)) != 0)
    {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
        {
            *ver = 0;
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_asn1_get_int(p, end, ver)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION, ret);
    }

    if (*p != end)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

// x509.c
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf *serial)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_PRIMITIVE | 2) &&
        **p != MBEDTLS_ASN1_INTEGER)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    serial->tag = *(*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &serial->len)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }

    serial->p = *p;
    *p += serial->len;

    return 0;
}

int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg(p, end, alg, params)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_ALG, ret);
    }

    return 0;
}
/*
int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if ((ret = mbedtls_oid_get_sig_alg(sig_oid, md_alg, pk_alg)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG, ret);
    }

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if (*pk_alg == MBEDTLS_PK_RSASSA_PSS) {
        mbedtls_pk_rsassa_pss_options *pss_opts;

        pss_opts = mbedtls_calloc(1, sizeof(mbedtls_pk_rsassa_pss_options));
        if (pss_opts == NULL) {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        ret = mbedtls_x509_get_rsassa_pss_params(sig_params,
                                                 md_alg,
                                                 &pss_opts->mgf1_hash_id,
                                                 &pss_opts->expected_salt_len);
        if (ret != 0) {
            mbedtls_free(pss_opts);
            return ret;
        }

        *sig_opts = (void *) pss_opts;
    } else
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
    {
        // Make sure parameters are absent or NULL
        if ((sig_params->tag != MBEDTLS_ASN1_NULL && sig_params->tag != 0) ||
            sig_params->len != 0) {
            return MBEDTLS_ERR_X509_INVALID_ALG;
        }
    }

    return 0;
}
*/