#include "include/custom_functions.h"
#include "include/custom_string.h"
#include "sha3/sha3.h"
#include "ed25519/ed25519.h"

// x509_create.c
const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++)
    {
        if (cur->name_len == name_len &&
            my_strncmp(cur->name, name, name_len) == 0)
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
    const char *end = s + strlen(s);//strlen(s);
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
                mbedtls_asn1_store_named_data(head, oid, strlen(oid),//strlen(oid),
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
    my_memcpy(*p, sig, len);

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

int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur_ext = first;

    while (cur_ext != NULL)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension(p, start, cur_ext));
        cur_ext = cur_ext->next;
    }

    return (int)len;
}

int x509_write_extension(unsigned char **p, unsigned char *start,
                         mbedtls_asn1_named_data *ext)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext->val.p + 1,
                                                            ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));

    if (ext->val.p[0] != 0)
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(p, start, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext->oid.p,
                                                            ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int mbedtls_x509_set_extension(mbedtls_asn1_named_data *head, const char *oid, size_t oid_len,
                               int critical, /*const*/ unsigned char *val, size_t val_len, int *ne)
{
    // mbedtls_asn1_named_data *cur;
    // int pos;
    // if ((/*cur =*/ pos = mbedtls_asn1_store_named_data_mod(head, oid, oid_len,
    //                                        NULL, val_len + 1, ne)) == 0) {
    // return MBEDTLS_ERR_X509_ALLOC_FAILED;
    //}
    /*
    head[0].oid.len = oid_len;
    my_memcpy(head[0].oid.p_arr[0], oid, oid_len);
    head[pos].val.p_arr[0] = critical;
    my_memcpy(head[pos].val.p_arr[1], val, val_len);
    */
    head[*ne].oid.len = oid_len;
    my_memcpy(head[*ne].oid.p_arr, oid, oid_len);
    head[*ne].val.p_arr[0] = critical;
    head[*ne].val.len = val_len;
    for (int i = 1; i < val_len; i++)
        head[*ne].val.p_arr[i] = val[i - 1];
    // my_memcpy(head[*ne].val.p_arr + 1, val, val_len);

    *ne = *ne + 1;

    return 0;
}

// x509write_crt.c
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    my_memset(ctx, 0, sizeof(mbedtls_x509write_cert));

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
    //ctx->ne_issue_arr = 0;
    //return mbedtls_x509_string_to_names_mod(&ctx->issuer_arr, issuer_name, &ctx->ne_issue_arr);
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
    if (my_strlen(not_before) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        my_strlen(not_after) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    my_strncpy(ctx->not_before, not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    my_strncpy(ctx->not_after, not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng) //, unsigned char* test, int *l_topass)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid = NULL;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char sig[64];
    // size_t hash_length = 0;
    unsigned char hash[64];

    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    sha3_ctx_t hash_ctx;

    /*
     * Prepare data to be signed at the end of the target buffer
     */

    // buf punta alla prima locazione di memoria del buffer,
    // se gli aggiungo la sua dimensione, ovvero size
    // il risultato sarà un puntatore alla fine del buffer, ovvero c
    c = buf + size;
    pk_alg = MBEDTLS_PK_ED25519;
    //    id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
    mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg, &sig_oid, &sig_oid_len);
    // sig_oid = "{0x2B, 0x65, 0x70}";
    // sig_oid_len = 3;

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if (ctx->version == MBEDTLS_X509_CRT_VERSION_3)
    {
        /*
        MBEDTLS_ASN1_CHK_ADD(len,
                            mbedtls_x509_write_extensions(&c,
                                                        buf, ctx->extensions));
        */
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_x509_write_extensions_mod(&c,
                                                               buf, ctx->extens_arr, ctx->ne_ext_arr));
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
    // il puntatore a dove si deve scrivere viene spostato della dimensione che occupa
    // la codifica della chiave pubblica in ASN1
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    /*
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names(&c, buf,
                                                  ctx->subject));
                                    */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names_mod(&c, buf,
                                                      ctx->subject_arr, ctx->ne_subje_arr));

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
    /*
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf,
                                                       ctx->issuer));
                                                       */

    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names_mod(&c, buf,
                                                      ctx->issuer_arr, ctx->ne_issue_arr));
    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(&c, buf,
                                                                 sig_oid, sig_oid_len, 0));

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
    /**
     *
     * Fase di firma, svolta con le funzioni già presenti in keystone
     *
     *  sha3_init(&hash_ctx, 64);
        sha3_update(&hash_ctx, c, len);
        sha3_final(hash, &hash_ctx);
     *
     * */
    /*
    for(int i = 0; i < len; i ++)
      test[i] = c[i];
    *l_topass = len;
*/
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, c, len);
    sha3_final(hash, &hash_ctx);
    // for(int i = 0; i < len; i ++)
    //  test[i] = c[i];
    // my_memcpy(test, hash, 64);

    /*
    if ((ret = mbedtls_pk_sign(ctx->issuer_key, ctx->md_alg,
                               hash, hash_length, sig, sizeof(sig), &sig_len,
                               f_rng, p_rng)) != 0)
                               {
        return ret;
    }
    */

    ed25519_sign(sig, hash, 64, ctx->issuer_key->pk_ctx.pub_key, ctx->issuer_key->pk_ctx.priv_key);
    sig_len = 64;

    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    my_memmove(buf, c, len);
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size;
    if (sig_oid != NULL)
    {
        MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, c,
                                                                     sig_oid, sig_oid_len, sig,
                                                                     sig_len));
    }

    /*
     * Memory layout after this step:
     *
     * buf       c=buf+len                c2            buf+size
     * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
     */

    /* Move raw CRT to just before the signature. */
    c = c2 - len;
    my_memmove(c, buf, len);

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
    my_memcpy(ctx->serial, serial, serial_len);

    return 0;
}

void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx,
                                      mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        /*const*/ unsigned char *val, size_t val_len)
{
    return mbedtls_x509_set_extension(ctx->extens_arr, oid, oid_len,
                                      critical, val, val_len, &ctx->ne_ext_arr);
}

// x509_crt.c
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               /*const*/ unsigned char *buf,
                               size_t buflen)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 1, NULL, NULL);
}

int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain,
                                        /*const*/ unsigned char *buf,
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
    /*
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
    */

    ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx);
    if (ret != 0)
    {
        if (prev)
        {
            prev->next = NULL;
        }
        /*
        if (crt != chain)
        {
            mbedtls_free(crt);
        }
        */
        return ret;
    }

    return 0;
}

void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
    my_memset(crt, 0, sizeof(mbedtls_x509_crt));
}

int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                            /*const*/ unsigned char *buf,
                            size_t buflen,
                            int make_copy,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end, *crt_end;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;

    my_memset(&sig_params1, 0, sizeof(mbedtls_x509_buf));
    my_memset(&sig_params2, 0, sizeof(mbedtls_x509_buf));
    my_memset(&sig_oid2, 0, sizeof(mbedtls_x509_buf));

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
        // mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    end = crt_end = p + len;
    crt->raw.len = crt_end - buf;
    if (make_copy != 0)
    {
        /* Create and populate a new buffer for the raw field. */
        /*
        crt->raw.p = p = mbedtls_calloc(1, crt->raw.len);
        if (crt->raw.p == NULL)
        {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        memcpy(crt->raw.p, buf, crt->raw.len);
        */
        // my_memcpy(crt->raw.p_arr, buf, crt->raw.len);
        crt->raw.p = buf;
        p = crt->raw.p;
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
        // mbedtls_x509_crt_free(crt);
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
        // mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->version < 0 || crt->version > 2)
    {
        // mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }

    crt->version++;

    if ((ret = mbedtls_x509_get_sig_alg_mod(&crt->sig_oid, &sig_params1,
                                            &crt->sig_md, &crt->sig_pk,
                                            &crt->sig_opts)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return ret;
    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    /*
    if ((ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    mbedtls_x509_name *app;
    app = &crt->issuer;
    while(app != NULL){
        for (int i = 0; i < app->val.len; i ++){
            printf("%c", app->val.p[i]);
        }
        printf("\n");
        app = app->next;
    }
    */
    if ((ret = mbedtls_x509_get_name_mod(&p, p + len, crt->issuer_arr, &crt->ne_issue_arr)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return ret;
    }
    /*
    for(int i = 0; i < crt->ne_issue_arr; i ++){
        printf("Parte di nome letta da memoria\n:");
        for(int j = 0; j < crt->issuer_arr[i].val.len; j++)
            printf("%c", crt->issuer_arr[i].val.p[j]);
        printf("\n");
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
        // mbedtls_x509_crt_free(crt);
        return ret;
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    /*
     if ((ret = mbedtls_x509_get_name_mod(&p, p + len, crt->issuer_arr, &crt->ne_issue_arr)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }*/
    if (len && (ret = mbedtls_x509_get_name_mod(&p, p + len, crt->subject_arr, &crt->ne_subje_arr)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return ret;
    }
    /*
     for(int i = 0; i < crt->ne_subje_arr; i ++){
        printf("Parte di nome letta da memoria\n:");
        for(int j = 0; j < crt->subject_arr[i].val.len; j++)
            printf("%c", crt->subject_arr[i].val.p[j]);
        printf("\n");
    }
    */
    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo
     */
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
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
            // mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 2 || crt->version == 3)
    {
        ret = x509_get_uid(&p, end, &crt->subject_id, 2);
        if (ret != 0)
        {
            // mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 3)
    {
        ret = x509_get_crt_ext(&p, end, crt, cb, p_ctx);
        if (ret != 0)
        {
            // mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (p != end)
    {
        // mbedtls_x509_crt_free(crt);
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
    if ((ret = mbedtls_x509_get_alg_mod(&p, end, &sig_oid2, &sig_params2)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->sig_oid.len != sig_oid2.len ||
        my_memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 ||
        sig_params1.tag != sig_params2.tag ||
        sig_params1.len != sig_params2.len ||
        (sig_params1.len != 0 &&
         my_memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0))
    {
        // mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_SIG_MISMATCH;
    }

    if ((ret = mbedtls_x509_get_sig(&p, end, &crt->sig)) != 0)
    {
        // mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (p != end)
    {
        // mbedtls_x509_crt_free(crt);
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
            //mbedtls_platform_zeroize(cert_cur->raw.p, cert_cur->raw.len);
            mbedtls_free(cert_cur->raw.p);
        }

        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        //mbedtls_platform_zeroize(cert_prv, sizeof(mbedtls_x509_crt));
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

int x509_get_dates(unsigned char **p,
                   const unsigned char *end,
                   mbedtls_x509_time *from,
                   mbedtls_x509_time *to)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_x509_get_time(p, end, from)) != 0)
    {
        return ret;
    }

    if ((ret = mbedtls_x509_get_time(p, end, to)) != 0)
    {
        return ret;
    }

    if (*p != end)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int x509_get_uid(unsigned char **p,
                 const unsigned char *end,
                 mbedtls_x509_buf *uid, int n)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*p == end)
    {
        return 0;
    }

    uid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &uid->len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                        n)) != 0)
    {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
        {
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    uid->p = *p;
    *p += uid->len;

    return 0;
}

int x509_get_crt_ext(unsigned char **p,
                     const unsigned char *end,
                     mbedtls_x509_crt *crt,
                     mbedtls_x509_crt_ext_cb_t cb,
                     void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data, /* *start_ext_octet,*/ *end_ext_octet;

    if (*p == end)
    {
        return 0;
    }

    if ((ret = mbedtls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0)
    {
        return ret;
    }

    end = crt->v3_ext.p + crt->v3_ext.len;
    while (*p < end)
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        // int ext_type = 0;

        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
        {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0)
        {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG))
        {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0)
        {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        // start_ext_octet = *p;
        end_ext_octet = *p + len;

        if (end_ext_octet != end_ext_data)
        {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        // my_memcpy(crt->hash.p_arr,*p, 64);

        crt->hash.p = *p;
        crt->hash.len = 64;
        *p += 64;

        /*
         * Detect supported extensions
         */
        // ret = mbedtls_oid_get_x509_ext_type(&extn_oid, &ext_type);

        /*
        if (ret != 0)
        {
        // Give the callback (if any) a chance to handle the extension
            if (cb != NULL)
            {
                ret = cb(p_ctx, crt, &extn_oid, is_critical, *p, end_ext_octet);
                if (ret != 0 && is_critical)
                {
                    return ret;
                }
                *p = end_ext_octet;
                continue;
            }
        */
       
        /* No parser found, skip extension */
        //*p = end_ext_octet;

        /*
        if (is_critical)
        {
        // Data is marked as critical: fail
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
        }
        continue;
        }
        */
        /* Forbid repeated extensions */
        /*
        if ((crt->ext_types & ext_type) != 0)
        {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }

        crt->ext_types |= ext_type;
        */

        /**
         * Le extensions non vengono parsate come un array di tali, ma vanno direttamente a fillare il
         * campo corrrispettivo nella struttura
         *
         */
        /*
        switch (ext_type)
        {
        case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
            // Parse basic constraints
            if ((ret = x509_get_basic_constraints(p, end_ext_octet,
                                                  &crt->ca_istrue, &crt->max_pathlen)) != 0)
            {
                return ret;
            }
            break;

        case MBEDTLS_X509_EXT_KEY_USAGE:
            // Parse key usage
            if ((ret = mbedtls_x509_get_key_usage(p, end_ext_octet,
                                                  &crt->key_usage)) != 0)
            {
                return ret;
            }
            break;

        case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
            // Parse extended key usage
            if ((ret = x509_get_ext_key_usage(p, end_ext_octet,
                                              &crt->ext_key_usage)) != 0)
            {
                return ret;
            }
            break;

        case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
            // Parse subject alt name
            if ((ret = mbedtls_x509_get_subject_alt_name(p, end_ext_octet,
                                                         &crt->subject_alt_names)) != 0)
            {
                return ret;
            }
            break;

        case MBEDTLS_X509_EXT_NS_CERT_TYPE:
            // Parse netscape certificate type
            if ((ret = mbedtls_x509_get_ns_cert_type(p, end_ext_octet,
                                                     &crt->ns_cert_type)) != 0)
            {
                return ret;
            }
            break;

        case MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES:
            // Parse certificate policies type
            if ((ret = x509_get_certificate_policies(p, end_ext_octet,
                                                     &crt->certificate_policies)) != 0)
            {
                // Give the callback (if any) a chance to handle the extension
                 // if it contains unsupported policies
                if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE && cb != NULL &&
                    cb(p_ctx, crt, &extn_oid, is_critical,
                       start_ext_octet, end_ext_octet) == 0)
                       {
                    break;
                }

                if (is_critical)
                {
                    return ret;
                }
                else
                //
                 // If MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE is returned, then we
                 // cannot interpret or enforce the policy. However, it is up to
                 // the user to choose how to enforce the policies,
                 // unless the extension is critical.
                 //
                if (ret != MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE)
                {
                    return ret;
                }
            }
            break;
        */
        // default:
        /*
         * If this is a non-critical extension, which the oid layer
         * supports, but there isn't an x509 parser for it,
         * skip the extension.
         */
        /*
            if (is_critical)
            {
                return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
            }
            else
            {
                *p = end_ext_octet;
            }
        }
        */
    }

    if (*p != end)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

// x509.c
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf_crt *serial)
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
                         mbedtls_x509_buf_crt *alg, mbedtls_x509_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg_mod(p, end, alg, params)) != 0)
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
    //int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    *pk_alg = MBEDTLS_PK_ED25519;
    *md_alg = MBEDTLS_MD_SHA384;

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
/*
int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len;
    const unsigned char *end_set;
    mbedtls_x509_name *head = cur;

    // don't use recursion, we'd risk stack overflow if not optimized
    while (1) {

         // parse SET
        if ((ret = mbedtls_asn1_get_tag(p, end, &set_len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
            goto error;
        }

        end_set  = *p + set_len;

        while (1) {
            if ((ret = x509_get_attr_type_value(p, end_set, cur)) != 0) {
                goto error;
            }

            if (*p == end_set) {
                break;
            }

            // Mark this item as being no the only one in a set
            cur->next_merged = 1;

            cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_name));

            if (cur->next == NULL) {
                ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
                goto error;
            }

            cur = cur->next;
        }

         // continue until end of SEQUENCE is reached
        if (*p == end) {
            return 0;
        }

        cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_name));

        if (cur->next == NULL) {
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto error;
        }

        cur = cur->next;
    }

error:
    // Skip the first element as we did not allocate it
    mbedtls_asn1_free_named_data_list_shallow(head->next);
    head->next = NULL;

    return ret;
}
*/

int x509_get_attr_type_value(unsigned char **p,
                             const unsigned char *end,
                             mbedtls_x509_name *cur)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_x509_buf *oid;
    mbedtls_x509_buf *val;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    end = *p + len;

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    oid = &cur->oid;
    oid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    oid->p = *p;
    *p += oid->len;

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != MBEDTLS_ASN1_BMP_STRING && **p != MBEDTLS_ASN1_UTF8_STRING &&
        **p != MBEDTLS_ASN1_T61_STRING && **p != MBEDTLS_ASN1_PRINTABLE_STRING &&
        **p != MBEDTLS_ASN1_IA5_STRING && **p != MBEDTLS_ASN1_UNIVERSAL_STRING &&
        **p != MBEDTLS_ASN1_BIT_STRING)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    val = &cur->val;
    val->tag = *(*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &val->len)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    val->p = *p;
    *p += val->len;

    if (*p != end)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    cur->next = NULL;

    return 0;
}

int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_time *tm)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len, year_len;
    unsigned char tag;

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    tag = **p;

    if (tag == MBEDTLS_ASN1_UTC_TIME)
    {
        year_len = 2;
    }
    else if (tag == MBEDTLS_ASN1_GENERALIZED_TIME)
    {
        year_len = 4;
    }
    else
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    (*p)++;
    ret = mbedtls_asn1_get_len(p, end, &len);

    if (ret != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }

    return x509_parse_time(p, len, year_len, tm);
}

int x509_parse_time(unsigned char **p, size_t len, size_t yearlen,
                    mbedtls_x509_time *tm)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if (len < yearlen + 8)
    {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK(x509_parse_int(p, yearlen, &tm->year));
    if (2 == yearlen)
    {
        if (tm->year < 50)
        {
            tm->year += 100;
        }

        tm->year += 1900;
    }

    CHECK(x509_parse_int(p, 2, &tm->mon));
    CHECK(x509_parse_int(p, 2, &tm->day));
    CHECK(x509_parse_int(p, 2, &tm->hour));
    CHECK(x509_parse_int(p, 2, &tm->min));

    /*
     * Parse seconds if present
     */
    if (len >= 2)
    {
        CHECK(x509_parse_int(p, 2, &tm->sec));
        len -= 2;
    }
    else
    {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }

    /*
     * Parse trailing 'Z' if present
     */
    if (1 == len && 'Z' == **p)
    {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if (0 != len)
    {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }

    CHECK(x509_date_is_valid(tm));

    return 0;
}

int x509_parse_int(unsigned char **p, size_t n, int *res)
{
    *res = 0;

    for (; n > 0; --n)
    {
        if ((**p < '0') || (**p > '9'))
        {
            return MBEDTLS_ERR_X509_INVALID_DATE;
        }

        *res *= 10;
        *res += (*(*p)++ - '0');
    }

    return 0;
}

int x509_date_is_valid(const mbedtls_x509_time *t)
{
    int ret = MBEDTLS_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE(0, 9999, t->year);
    CHECK_RANGE(0, 23, t->hour);
    CHECK_RANGE(0, 59, t->min);
    CHECK_RANGE(0, 59, t->sec);

    switch (t->mon)
    {
    case 1:
    case 3:
    case 5:
    case 7:
    case 8:
    case 10:
    case 12:
        month_len = 31;
        break;
    case 4:
    case 6:
    case 9:
    case 11:
        month_len = 30;
        break;
    case 2:
        if ((!(t->year % 4) && t->year % 100) ||
            !(t->year % 400))
        {
            month_len = 29;
        }
        else
        {
            month_len = 28;
        }
        break;
    default:
        return ret;
    }
    CHECK_RANGE(1, month_len, t->day);

    return 0;
}

int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    int tag_type;

    if ((end - *p) < 1)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SIGNATURE,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    tag_type = **p;

    if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SIGNATURE, ret);
    }

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    /*
    printf("FIRMA OID\n");
    for(int i =0; i <64; i ++){
        printf("%02x-",sig->p[i]);
    }
    printf("\n");
    */
    *p += len;

    return 0;
}

int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *ext, int tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /* Extension structure use EXPLICIT tagging. That is, the actual
     * `Extensions` structure is wrapped by a tag-length pair using
     * the respective context-specific tag. */
    ret = mbedtls_asn1_get_tag(p, end, &ext->len,
                               MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag);
    if (ret != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    ext->tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (end != *p + len)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}
