#include "include/custom_functions.h"
#include "include/custom_string.h"

// asn1parse.c
void mbedtls_asn1_free_named_data_list(mbedtls_asn1_named_data **head)
{
    mbedtls_asn1_named_data *cur;

    while ((cur = *head) != NULL)
    {
        *head = cur->next;
        mbedtls_free(cur->oid.p);
        mbedtls_free(cur->val.p);
        mbedtls_free(cur);
    }
}

int mbedtls_asn1_get_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params)
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
        mbedtls_platform_zeroize(params, sizeof(mbedtls_asn1_buf));
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
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(
    mbedtls_asn1_named_data **head,
    const char *oid, size_t oid_len,
    const unsigned char *val,
    size_t val_len)
{
    mbedtls_asn1_named_data *cur;

    if ((cur = asn1_find_named_data(*head, oid, oid_len)) == NULL)
    {
        // Add new entry if not present yet based on OID
        //
        cur = (mbedtls_asn1_named_data *)mbedtls_calloc(1,
                                                        sizeof(mbedtls_asn1_named_data));
        if (cur == NULL)
        {
            return NULL;
        }

        cur->oid.len = oid_len;
        cur->oid.p = mbedtls_calloc(1, oid_len);
        if (cur->oid.p == NULL)
        {
            mbedtls_free(cur);
            return NULL;
        }

        memcpy(cur->oid.p, oid, oid_len);

        cur->val.len = val_len;
        if (val_len != 0)
        {
            cur->val.p = mbedtls_calloc(1, val_len);
            if (cur->val.p == NULL)
            {
                mbedtls_free(cur->oid.p);
                mbedtls_free(cur);
                return NULL;
            }
        }

        cur->next = *head;
        *head = cur;
    }
    else if (val_len == 0)
    {
        mbedtls_free(cur->val.p);
        cur->val.p = NULL;
    }
    else if (cur->val.len != val_len)
    {
        /*
         * Enlarge existing value buffer if needed
         * Preserve old data until the allocation succeeded, to leave list in
         * a consistent state in case allocation fails.
         */
        void *p = mbedtls_calloc(1, val_len);
        if (p == NULL)
        {
            return NULL;
        }

        mbedtls_free(cur->val.p);
        cur->val.p = p;
        cur->val.len = val_len;
    }

    if (val != NULL && val_len != 0)
    {
        memcpy(cur->val.p, val, val_len);
    }

    return cur;
}

mbedtls_asn1_named_data *asn1_find_named_data(
    mbedtls_asn1_named_data *list,
    const char *oid, size_t len)
{
    while (list != NULL)
    {
        if (list->oid.len == len &&
            memcmp(list->oid.p, oid, len) == 0)
        {
            break;
        }

        list = list->next;
    }

    return list;
}

// x509.c
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

int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL)
    {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if ((ret = mbedtls_oid_get_sig_alg(sig_oid, md_alg, pk_alg)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG, ret);
    }

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if (*pk_alg == MBEDTLS_PK_RSASSA_PSS)
    {
        mbedtls_pk_rsassa_pss_options *pss_opts;

        pss_opts = mbedtls_calloc(1, sizeof(mbedtls_pk_rsassa_pss_options));
        if (pss_opts == NULL)
        {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        ret = mbedtls_x509_get_rsassa_pss_params(sig_params,
                                                 md_alg,
                                                 &pss_opts->mgf1_hash_id,
                                                 &pss_opts->expected_salt_len);
        if (ret != 0)
        {
            mbedtls_free(pss_opts);
            return ret;
        }

        *sig_opts = (void *)pss_opts;
    }
    else
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
    {
        /* Make sure parameters are absent or NULL */
        if ((sig_params->tag != MBEDTLS_ASN1_NULL && sig_params->tag != 0) ||
            sig_params->len != 0)
        {
            return MBEDTLS_ERR_X509_INVALID_ALG;
        }
    }

    return 0;
}

int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len;
    const unsigned char *end_set;
    mbedtls_x509_name *head = cur;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while (1)
    {
        /*
         * parse SET
         */
        if ((ret = mbedtls_asn1_get_tag(p, end, &set_len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0)
        {
            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
            goto error;
        }

        end_set = *p + set_len;

        while (1)
        {
            if ((ret = x509_get_attr_type_value(p, end_set, cur)) != 0)
            {
                goto error;
            }

            if (*p == end_set)
            {
                break;
            }

            /* Mark this item as being no the only one in a set */
            cur->next_merged = 1;

            cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_name));

            if (cur->next == NULL)
            {
                ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
                goto error;
            }

            cur = cur->next;
        }

        /*
         * continue until end of SEQUENCE is reached
         */
        if (*p == end)
        {
            return 0;
        }

        cur->next = mbedtls_calloc(1, sizeof(mbedtls_x509_name));

        if (cur->next == NULL)
        {
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto error;
        }

        cur = cur->next;
    }

error:
    /* Skip the first element as we did not allocate it */
    mbedtls_asn1_free_named_data_list_shallow(head->next);
    head->next = NULL;

    return ret;
}

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

// x509_create.c
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

    /* Clear existing chain if present */
    mbedtls_asn1_free_named_data_list(head);

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
            mbedtls_asn1_named_data *cur =
                mbedtls_asn1_store_named_data(head, oid, strlen(oid),
                                              (unsigned char *)data,
                                              d - data);

            if (cur == NULL)
            {
                return MBEDTLS_ERR_X509_ALLOC_FAILED;
            }

            // set tagType
            cur->val.tag = attr_descr->default_tag;

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
int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx,
                                           const char *subject_name)
{
    return mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx,
                                          const char *issuer_name)
{
    return mbedtls_x509_string_to_names(&ctx->issuer, issuer_name);
}