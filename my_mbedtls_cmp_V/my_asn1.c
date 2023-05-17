// asn1parse.c
int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len)
{
    if ((end - *p) < 1)
    {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if ((**p & 0x80) == 0)
    {
        *len = *(*p)++;
    }
    else
    {
        switch (**p & 0x7F)
        {
        case 1:
            if ((end - *p) < 2)
            {
                return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if ((end - *p) < 3)
            {
                return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }

            *len = ((size_t)(*p)[1] << 8) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if ((end - *p) < 4)
            {
                return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }

            *len = ((size_t)(*p)[1] << 16) |
                   ((size_t)(*p)[2] << 8) | (*p)[3];
            (*p) += 4;
            break;

        case 4:
            if ((end - *p) < 5)
            {
                return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }

            *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) |
                   ((size_t)(*p)[3] << 8) | (*p)[4];
            (*p) += 5;
            break;

        default:
            return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        }
    }

    if (*len > (size_t)(end - *p))
    {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    return 0;
}

int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag)
{
    if ((end - *p) < 1)
    {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if (**p != tag)
    {
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }

    (*p)++;

    return mbedtls_asn1_get_len(p, end, len);
}

int mbedtls_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_BOOLEAN)) != 0)
    {
        return ret;
    }

    if (len != 1)
    {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    *val = (**p != 0) ? 1 : 0;
    (*p)++;

    return 0;
}

static int asn1_get_tagged_int(unsigned char **p,
                               const unsigned char *end,
                               int tag, int *val)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, tag)) != 0)
    {
        return ret;
    }

    /*
     * len==0 is malformed (0 must be represented as 020100 for INTEGER,
     * or 0A0100 for ENUMERATED tags
     */
    if (len == 0)
    {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    /* This is a cryptography library. Reject negative integers. */
    if ((**p & 0x80) != 0)
    {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    /* Skip leading zeros. */
    while (len > 0 && **p == 0)
    {
        ++(*p);
        --len;
    }

    /* Reject integers that don't fit in an int. This code assumes that
     * the int type has no padding bit. */
    if (len > sizeof(int))
    {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    if (len == sizeof(int) && (**p & 0x80) != 0)
    {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    *val = 0;
    while (len-- > 0)
    {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return 0;
}

int mbedtls_asn1_get_int(unsigned char **p,
                         const unsigned char *end,
                         int *val)
{
    return asn1_get_tagged_int(p, end, MBEDTLS_ASN1_INTEGER, val);
}

int mbedtls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
                                    size_t *len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_tag(p, end, len, MBEDTLS_ASN1_BIT_STRING)) != 0)
    {
        return ret;
    }

    if (*len == 0)
    {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    --(*len);

    if (**p != 0)
    {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    ++(*p);

    return 0;
}

void mbedtls_asn1_sequence_free(mbedtls_asn1_sequence *seq)
{
    while (seq != NULL)
    {
        mbedtls_asn1_sequence *next = seq->next;
        mbedtls_free(seq);
        seq = next;
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

void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name)
{
    for (mbedtls_asn1_named_data *next; name != NULL; name = next)
    {
        next = name->next;
        mbedtls_free(name);
    }
}

// asn1write.c
int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len)
{
    if (len < 0x80)
    {
        if (*p - start < 1)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char)len;
        return 1;
    }

    if (len <= 0xFF)
    {
        if (*p - start < 2)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char)len;
        *--(*p) = 0x81;
        return 2;
    }

    if (len <= 0xFFFF)
    {
        if (*p - start < 3)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = 0x82;
        return 3;
    }

    if (len <= 0xFFFFFF)
    {
        if (*p - start < 4)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = MBEDTLS_BYTE_2(len);
        *--(*p) = 0x83;
        return 4;
    }

    int len_is_valid = 1;
#if SIZE_MAX > 0xFFFFFFFF
    len_is_valid = (len <= 0xFFFFFFFF);
#endif
    if (len_is_valid)
    {
        if (*p - start < 5)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = MBEDTLS_BYTE_2(len);
        *--(*p) = MBEDTLS_BYTE_3(len);
        *--(*p) = 0x84;
        return 5;
    }

    return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
}

int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag)
{
    if (*p - start < 1)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = tag;

    return 1;
}

int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size)
{
    size_t len = 0;

    if (*p < start || (size_t)(*p - start) < size)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    memcpy(*p, buf, len);

    return (int)len;
}

int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    // Write NULL
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, 0));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_NULL));

    return (int)len;
}

int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *)oid, oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));

    return (int)len;
}

int mbedtls_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (par_len == 0)
    {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_null(p, start));
    }
    else
    {
        len += par_len;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid, oid_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                         MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}

int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p - start < 1)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BOOLEAN));

    return (int)len;
}

static int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    do
    {
        if (*p - start < 1)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        len += 1;
        *--(*p) = val & 0xff;
        val >>= 8;
    } while (val > 0);

    if (**p & 0x80)
    {
        if (*p - start < 1)
        {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));

    return (int)len;
}

int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val)
{
    return asn1_write_tagged_int(p, start, val, MBEDTLS_ASN1_INTEGER);
}

int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag,
                                     const char *text, size_t text_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *)text,
                                                            text_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));

    return (int)len;
}

static mbedtls_asn1_named_data *asn1_find_named_data(
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
