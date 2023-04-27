#include "custom_functions.h"
#include "custom_string.h"

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

// asn1write.c
int mbedtls_asn1_store_named_data_mod(mbedtls_asn1_named_data *head, const char *oid, size_t oid_len, const unsigned char *val, size_t val_len, int *ne)
{
    int pos;
    if (asn1_find_named_data_mod(head, oid, oid_len, *ne) == 0)
    {
        head[*ne].oid.len = oid_len;
        my_memcpy(head[*ne].oid.p_arr, oid, oid_len);
        head[*ne].val.len = val_len;
        my_memcpy(head[*ne].val.p_arr, val, val_len);
        *ne = *ne + 1;
        pos = *ne - 1;
    }
    return pos;
}

int asn1_find_named_data_mod(mbedtls_asn1_named_data *list, const char *oid, size_t len, size_t ne)
{
    int i = 0;
    while (i != ne)
    {
        if (list[i].oid.len == len &&
            my_memcmp(list[i].oid.p_arr, oid, len) == 0)
        {
            break;
        }
        i += 1;
    }
    if (i == ne)
        return 0;
    return 0;
    // return list;
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

int mbedtls_x509_get_name_mod(unsigned char **p, const unsigned char *end,
                              mbedtls_x509_name *cur, int *ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len;
    const unsigned char *end_set;
    mbedtls_x509_name *head = cur;
    *ne = 0;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while (1)
    {

        if ((ret = mbedtls_asn1_get_tag(p, end, &set_len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0)
        {
            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
            goto error;
        }

        end_set = *p + set_len;

        while (1)
        {
            if ((ret = x509_get_attr_type_value_mod(p, end_set, &head[*ne])) != 0)
            {
                goto error;
            }

            if (*p == end_set)
            {
                break;
            }

            /* Mark this item as being no the only one in a set */
            /*
            cur->next_merged = 1;
            */
        }
        *ne = *ne + 1;
        if (*p == end)
        {
            return 0;
        }
    }

error:
    /* Skip the first element as we did not allocate it */
    // mbedtls_asn1_free_named_data_list_shallow(head->next);
    head->next = NULL;

    return ret;
}

int x509_get_attr_type_value_mod(unsigned char **p,
                                 const unsigned char *end,
                                 mbedtls_asn1_named_data *cur)
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
    return 0;
}

// x509_create.c
int mbedtls_x509_write_extensions_mod(unsigned char **p, unsigned char *start,
                                      mbedtls_asn1_named_data *arr_exte, int ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    int i = 0;
    // mbedtls_asn1_named_data *cur_ext = first;

    while (i != ne)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension_mod(p, start, arr_exte[i]));
        i = i + 1;
    }

    return (int)len;
}

int x509_write_extension_mod(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data ext)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, &ext.val.p_arr[1],
                                                            ext.val.len - 1));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext.val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));

    if (ext.val.p_arr[0] != 0)
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(p, start, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext.oid.p_arr,
                                                            ext.oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext.oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int mbedtls_x509_string_to_names_mod(mbedtls_asn1_named_data *head, const char *name, int *ne)
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + my_strlen(s); // my_strlen(s);
    const char *oid = NULL;
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_tag = 1;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    /* Clear existing chain if present */
    mbedtls_asn1_free_named_data_list_mod(ne);

    while (c <= end)
    {
        if (in_tag && *c == '=')
        {
            if ((attr_descr = x509_attr_descr_from_name(s, c - s)) == NULL)
            {
                ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end)
        {
            c++;

            /* Check for valid escaped characters */
            if (c == end || *c != ',')
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }
        else if (!in_tag && (*c == ',' || c == end))
        {
            int pos =
                mbedtls_asn1_store_named_data_mod(head, oid, my_strlen(oid), // my_strlen(oid),
                                                  (unsigned char *)data,
                                                  d - data, ne);
            /*
            if (cur == NULL) {
                return MBEDTLS_ERR_X509_ALLOC_FAILED;
            }
            */
            // set tagType
            head[pos].val.tag = attr_descr->default_tag;
            // cur->val.tag = attr_descr->default_tag;

            while (c < end && *(c + 1) == ' ')
            {
                c++;
            }

            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1)
        {
            *(d++) = *c;

            if (d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE)
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return ret;
}

int mbedtls_x509_write_names_mod(unsigned char **p, unsigned char *start,
                                 mbedtls_asn1_named_data *arr, int ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    for (int i = 0; i < ne; i++)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_name_mod(p, start, arr[i]));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int x509_write_name_mod(unsigned char **p,
                        unsigned char *start,
                        mbedtls_asn1_named_data cur_name)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid = (const char *)cur_name.oid.p_arr;
    size_t oid_len = cur_name.oid.len;
    const unsigned char *name = cur_name.val.p_arr;
    size_t name_len = cur_name.val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name.val.tag,
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
int mbedtls_x509write_crt_set_subject_name_mod(mbedtls_x509write_cert *ctx, const char *subject_name)
{
    ctx->ne_subje_arr = 0;
    return mbedtls_x509_string_to_names_mod(ctx->subject_arr, subject_name, &ctx->ne_subje_arr);
}

int mbedtls_x509write_crt_set_issuer_name_mod(mbedtls_x509write_cert *ctx, const char *issuer_name)
{
    ctx->ne_issue_arr = 0;
    return mbedtls_x509_string_to_names_mod(ctx->issuer_arr, issuer_name, &ctx->ne_issue_arr);
}