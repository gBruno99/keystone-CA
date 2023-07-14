#include "custom_functions.h"

// asn1parse.c
int custom_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len)
{
    if ((end - *p) < 1) {
        return CUSTOM_ERR_ASN1_OUT_OF_DATA;
    }

    if ((**p & 0x80) == 0) {
        *len = *(*p)++;
    } else {
        switch (**p & 0x7F) {
            case 1:
                if ((end - *p) < 2) {
                    return CUSTOM_ERR_ASN1_OUT_OF_DATA;
                }

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3) {
                    return CUSTOM_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4) {
                    return CUSTOM_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 16) |
                       ((size_t) (*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5) {
                    return CUSTOM_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 24) | ((size_t) (*p)[2] << 16) |
                       ((size_t) (*p)[3] << 8) |           (*p)[4];
                (*p) += 5;
                break;

            default:
                return CUSTOM_ERR_ASN1_INVALID_LENGTH;
        }
    }

    if (*len > (size_t) (end - *p)) {
        return CUSTOM_ERR_ASN1_OUT_OF_DATA;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_get_len - len = %lu\n", *len);
    #endif
    return 0;
}

int custom_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag)
{
    if ((end - *p) < 1) {
        return CUSTOM_ERR_ASN1_OUT_OF_DATA;
    }

    if (**p != tag) {
        return CUSTOM_ERR_ASN1_UNEXPECTED_TAG;
    }

    (*p)++;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_get_tag - tag = %02x\n", tag);
    #endif
    return custom_asn1_get_len(p, end, len);
}

int custom_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = custom_asn1_get_tag(p, end, &len, CUSTOM_ASN1_BOOLEAN)) != 0) {
        return ret;
    }

    if (len != 1) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }

    *val = (**p != 0) ? 1 : 0;
    (*p)++;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_get_bool - bool = %d\n", *val);
    #endif
    return 0;
}

static int asn1_get_tagged_int(unsigned char **p,
                               const unsigned char *end,
                               int tag, int *val)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = custom_asn1_get_tag(p, end, &len, tag)) != 0) {
        return ret;
    }

    /*
     * len==0 is malformed (0 must be represented as 020100 for INTEGER,
     * or 0A0100 for ENUMERATED tags
     */
    if (len == 0) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }
    /* This is a cryptography library. Reject negative integers. */
    if ((**p & 0x80) != 0) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }

    /* Skip leading zeros. */
    while (len > 0 && **p == 0) {
        ++(*p);
        --len;
    }

    /* Reject integers that don't fit in an int. This code assumes that
     * the int type has no padding bit. */
    if (len > sizeof(int)) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }
    if (len == sizeof(int) && (**p & 0x80) != 0) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }

    *val = 0;
    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("asn1_get_tagged_int - int = %d\n", *val);
    #endif
    return 0;
}

int custom_asn1_get_int(unsigned char **p,
                         const unsigned char *end,
                         int *val)
{
    return asn1_get_tagged_int(p, end, CUSTOM_ASN1_INTEGER, val);
}

int custom_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
                               custom_asn1_bitstring *bs)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    /* Certificate type is a single byte bitstring */
    if ((ret = custom_asn1_get_tag(p, end, &bs->len, CUSTOM_ASN1_BIT_STRING)) != 0) {
        return ret;
    }

    /* Check length, subtract one for actual bit string length */
    if (bs->len < 1) {
        return CUSTOM_ERR_ASN1_OUT_OF_DATA;
    }
    bs->len -= 1;

    /* Get number of unused bits, ensure unused bits <= 7 */
    bs->unused_bits = **p;
    if (bs->unused_bits > 7) {
        return CUSTOM_ERR_ASN1_INVALID_LENGTH;
    }
    (*p)++;

    /* Get actual bitstring */
    bs->p = *p;
    *p += bs->len;

    if (*p != end) {
        return CUSTOM_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}

int custom_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
                                    size_t *len)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = custom_asn1_get_tag(p, end, len, CUSTOM_ASN1_BIT_STRING)) != 0) {
        return ret;
    }

    if (*len == 0) {
        return CUSTOM_ERR_ASN1_INVALID_DATA;
    }
    --(*len);

    if (**p != 0) {
        return CUSTOM_ERR_ASN1_INVALID_DATA;
    }
    ++(*p);

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_get_bitstring_null - len = %lu\n", *len);
    #endif

    return 0;
}

void custom_asn1_sequence_free(custom_asn1_sequence *seq)
{
    while (seq != NULL) {
        custom_asn1_sequence *next = seq->next;
        custom_free(seq);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_sequence_free - free: %lu\n", sizeof(custom_asn1_sequence));
        #endif
        seq = next;
    }
}

int custom_asn1_get_alg(unsigned char **p,
                         const unsigned char *end,
                         custom_asn1_buf *alg, custom_asn1_buf *params)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    if ((end - *p) < 1) {
        return CUSTOM_ERR_ASN1_OUT_OF_DATA;
    }

    alg->tag = **p;
    end = *p + len;

    if ((ret = custom_asn1_get_tag(p, end, &alg->len, CUSTOM_ASN1_OID)) != 0) {
        return ret;
    }

    alg->p = *p;
    *p += alg->len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_asn1_get_alg - alg", alg->p, alg->len);
    printf("custom_asn1_get_alg - alg_tag = %02x\n", alg->tag);
    #endif

    if (*p == end) {
        custom_platform_zeroize(params, sizeof(custom_asn1_buf));
        return 0;
    }

    params->tag = **p;
    (*p)++;

    if ((ret = custom_asn1_get_len(p, end, &params->len)) != 0) {
        return ret;
    }

    params->p = *p;
    *p += params->len;

    if (*p != end) {
        return CUSTOM_ERR_ASN1_LENGTH_MISMATCH;
    }

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_asn1_get_alg - params", params->p, params->len);
    printf("custom_asn1_get_alg - params_tag = %02x\n", params->tag);
    #endif

    return 0;
}

void custom_asn1_free_named_data_list(custom_asn1_named_data **head)
{
    custom_asn1_named_data *cur;

    while ((cur = *head) != NULL) {
        *head = cur->next;
        custom_free(cur->oid.p);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_free_named_data_list - free: %lu\n", cur->oid.len);
        #endif
        custom_free(cur->val.p);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_free_named_data_list - free: %lu\n", cur->val.len);
        #endif
        custom_free(cur);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_free_named_data_list - free: %lu\n", sizeof(custom_asn1_named_data));
        #endif
    }
}

void custom_asn1_free_named_data_list_shallow(custom_asn1_named_data *name)
{
    for (custom_asn1_named_data *next; name != NULL; name = next) {
        next = name->next;
        custom_free(name);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_free_named_data_list_shallow - free: %lu\n", sizeof(custom_asn1_named_data));
        #endif
    }
}

// asn1write.c
int custom_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_len - len = %lu\n", len);
    #endif
    if (len < 0x80) {
        if (*p - start < 1) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char) len;
        return 1;
    }

    if (len <= 0xFF) {
        if (*p - start < 2) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return 2;
    }

    if (len <= 0xFFFF) {
        if (*p - start < 3) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = CUSTOM_BYTE_0(len);
        *--(*p) = CUSTOM_BYTE_1(len);
        *--(*p) = 0x82;
        return 3;
    }

    if (len <= 0xFFFFFF) {
        if (*p - start < 4) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = CUSTOM_BYTE_0(len);
        *--(*p) = CUSTOM_BYTE_1(len);
        *--(*p) = CUSTOM_BYTE_2(len);
        *--(*p) = 0x83;
        return 4;
    }

    int len_is_valid = 1;
    /* // new_impl
#if SIZE_MAX > 0xFFFFFFFF
    len_is_valid = (len <= 0xFFFFFFFF);
#endif
    */
    if (len_is_valid) {
        if (*p - start < 5) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = CUSTOM_BYTE_0(len);
        *--(*p) = CUSTOM_BYTE_1(len);
        *--(*p) = CUSTOM_BYTE_2(len);
        *--(*p) = CUSTOM_BYTE_3(len);
        *--(*p) = 0x84;
        return 5;
    }

    return CUSTOM_ERR_ASN1_INVALID_LENGTH;
}

int custom_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_tag - tag = %02x\n", tag);
    #endif
    if (*p - start < 1) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = tag;

    return 1;
}

int custom_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size)
{
    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_asn1_write_raw_buffer - buf", (unsigned char *) buf, (int)size);
    #endif
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    custom_memcpy(*p, buf, len);

    return (int) len;
}

int custom_asn1_write_null(unsigned char **p, const unsigned char *start)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_null\n");
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    // Write NULL
    //
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, 0));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_NULL));

    return (int) len;
}

int custom_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len)
{
    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_asn1_write_oid - buf", (unsigned char *)oid, (int)oid_len);
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *) oid, oid_len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_OID));

    return (int) len;
}

int custom_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_algorithm_identifier\n");
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (par_len == 0) {
        CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_null(p, start));
    } else {
        len += par_len;
    }

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_oid(p, start, oid, oid_len));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start,
                                                     CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SEQUENCE));

    return (int) len;
}

int custom_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_bool - bool = %d\n", boolean);
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p - start < 1) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_BOOLEAN));

    return (int) len;
}

static int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("asn1_write_tagged_int - val = %d, tag = %d\n", val, tag);
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    do {
        if (*p - start < 1) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }
        len += 1;
        *--(*p) = val & 0xff;
        val >>= 8;
    } while (val > 0);

    if (**p & 0x80) {
        if (*p - start < 1) {
            return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
        }
        *--(*p) = 0x00;
        len += 1;
    }

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, tag));

    return (int) len;
}

int custom_asn1_write_int(unsigned char **p, const unsigned char *start, int val)
{
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_asn1_write_int - val = %d\n", val);
    #endif
    return asn1_write_tagged_int(p, start, val, CUSTOM_ASN1_INTEGER);
}

int custom_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag,
                                     const char *text, size_t text_len)
{
    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_asn1_write_tagged_string - buf", (unsigned char*)text, text_len);
    printf("custom_asn1_write_tagged_string - tag = %d\n", tag);
    #endif
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *) text,
                                                            text_len));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, tag));

    return (int) len;
}

int custom_asn1_write_named_bitstring(unsigned char **p,
                                       const unsigned char *start,
                                       const unsigned char *buf,
                                       size_t bits)
{
    size_t unused_bits, byte_len;
    const unsigned char *cur_byte;
    unsigned char cur_byte_shifted;
    unsigned char bit;

    byte_len = (bits + 7) / 8;
    unused_bits = (byte_len * 8) - bits;

    /*
     * Named bitstrings require that trailing 0s are excluded in the encoding
     * of the bitstring. Trailing 0s are considered part of the 'unused' bits
     * when encoding this value in the first content octet
     */
    if (bits != 0) {
        cur_byte = buf + byte_len - 1;
        cur_byte_shifted = *cur_byte >> unused_bits;

        for (;;) {
            bit = cur_byte_shifted & 0x1;
            cur_byte_shifted >>= 1;

            if (bit != 0) {
                break;
            }

            bits--;
            if (bits == 0) {
                break;
            }

            if (bits % 8 == 0) {
                cur_byte_shifted = *--cur_byte;
            }
        }
    }

    return custom_asn1_write_bitstring(p, start, buf, bits);
}

int custom_asn1_write_bitstring(unsigned char **p, const unsigned char *start,
                                 const unsigned char *buf, size_t bits)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    size_t unused_bits, byte_len;

    byte_len = (bits + 7) / 8;
    unused_bits = (byte_len * 8) - bits;

    if (*p < start || (size_t) (*p - start) < byte_len + 1) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = byte_len + 1;

    /* Write the bitstring. Ensure the unused bits are zeroed */
    if (byte_len > 0) {
        byte_len--;
        *--(*p) = buf[byte_len] & ~((0x1 << unused_bits) - 1);
        (*p) -= byte_len;
        custom_memcpy(*p, buf, byte_len);
    }

    /* Write unused bits */
    *--(*p) = (unsigned char) unused_bits;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_BIT_STRING));

    return (int) len;
}

static custom_asn1_named_data *asn1_find_named_data(
    custom_asn1_named_data *list,
    const char *oid, size_t len)
{
    while (list != NULL) {
        if (list->oid.len == len &&
            custom_memcmp(list->oid.p, oid, len) == 0) {
            break;
        }

        list = list->next;
    }

    return list;
}

custom_asn1_named_data *custom_asn1_store_named_data(
    custom_asn1_named_data **head,
    const char *oid, size_t oid_len,
    const unsigned char *val,
    size_t val_len)
{
    custom_asn1_named_data *cur;

    if ((cur = asn1_find_named_data(*head, oid, oid_len)) == NULL) {
        // Add new entry if not present yet based on OID
        //
        cur = (custom_asn1_named_data *) custom_calloc(1,
                                                         sizeof(custom_asn1_named_data));
        if (cur == NULL) {
            return NULL;
        }

        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_store_named_data - calloc: %lu\n", sizeof(custom_asn1_named_data));
        #endif

        cur->oid.len = oid_len;
        cur->oid.p = custom_calloc(1, oid_len);
        if (cur->oid.p == NULL) {
            custom_free(cur);
            #if CUSTOM_DEBUG_PRINTS
            printf("custom_asn1_store_named_data - free: %lu\n", sizeof(custom_asn1_named_data));
            #endif
            return NULL;
        }

        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_store_named_data - calloc: %lu\n", oid_len);
        #endif

        custom_memcpy(cur->oid.p, oid, oid_len);

        cur->val.len = val_len;
        if (val_len != 0) {
            cur->val.p = custom_calloc(1, val_len);
            if (cur->val.p == NULL) {
                custom_free(cur->oid.p);
                #if CUSTOM_DEBUG_PRINTS
                printf("custom_asn1_store_named_data - free: %lu\n", cur->val.len);
                #endif
                custom_free(cur);
                #if CUSTOM_DEBUG_PRINTS
                printf("custom_asn1_store_named_data - free: %lu\n", sizeof(custom_asn1_named_data));
                #endif
                return NULL;
            }
            #if CUSTOM_DEBUG_PRINTS
            printf("custom_asn1_store_named_data - calloc: %lu\n", val_len);
            #endif
        }

        cur->next = *head;
        *head = cur;
    } else if (val_len == 0) {
        custom_free(cur->val.p);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_store_named_data - free: %lu\n", cur->val.len);
        #endif
        cur->val.p = NULL;
    } else if (cur->val.len != val_len) {
        /*
         * Enlarge existing value buffer if needed
         * Preserve old data until the allocation succeeded, to leave list in
         * a consistent state in case allocation fails.
         */
        void *p = custom_calloc(1, val_len);
        if (p == NULL) {
            return NULL;
        }

        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_store_named_data - calloc: %lu\n", val_len);
        #endif
        custom_free(cur->val.p);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_asn1_store_named_data - free: %lu\n", cur->val.len);
        #endif
        cur->val.p = p;
        cur->val.len = val_len;
    }

    if (val != NULL && val_len != 0) {
        custom_memcpy(cur->val.p, val, val_len);
    }

    return cur;
}
