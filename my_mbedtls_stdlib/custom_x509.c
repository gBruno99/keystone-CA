#include "custom_functions.h"

// x509.c
#define CHECK(code) if ((ret = (code)) != 0) { return ret; }
#define CHECK_RANGE(min, max, val)                      \
    do                                                  \
    {                                                   \
        if ((val) < (min) || (val) > (max))    \
        {                                               \
            return ret;                              \
        }                                               \
    } while (0)

int custom_x509_get_serial(unsigned char **p, const unsigned char *end,
                            custom_x509_buf *serial)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    if ((end - *p) < 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_SERIAL,
                                 CUSTOM_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_ASN1_PRIMITIVE | 2) &&
        **p !=   CUSTOM_ASN1_INTEGER) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_SERIAL,
                                 CUSTOM_ERR_ASN1_UNEXPECTED_TAG);
    }

    serial->tag = *(*p)++;

    if ((ret = custom_asn1_get_len(p, end, &serial->len)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_SERIAL, ret);
    }

    serial->p = *p;
    *p += serial->len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_serial - serial", serial->p, serial->len);
    printf("custom_x509_get_serial - serial_tag = %02x\n", serial->tag);
    #endif
    return 0;
}

int custom_x509_get_alg(unsigned char **p, const unsigned char *end,
                         custom_x509_buf *alg, custom_x509_buf *params)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = custom_asn1_get_alg(p, end, alg, params)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_ALG, ret);
    }

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_alg - alg", alg->p, alg->len);
    printf("custom_x509_get_alg - alg_tag = %02x\n", alg->tag);
    print_hex_string("custom_x509_get_alg - params", params->p, params->len);
    printf("custom_x509_get_alg - params_tag = %02x\n", params->tag);
    #endif
    return 0;
}

static int x509_get_attr_type_value(unsigned char **p,
                                    const unsigned char *end,
                                    custom_x509_name *cur)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    custom_x509_buf *oid;
    custom_x509_buf *val;

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME, ret);
    }

    end = *p + len;

    if ((end - *p) < 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME,
                                 CUSTOM_ERR_ASN1_OUT_OF_DATA);
    }

    oid = &cur->oid;
    oid->tag = **p;

    if ((ret = custom_asn1_get_tag(p, end, &oid->len, CUSTOM_ASN1_OID)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME, ret);
    }

    oid->p = *p;
    *p += oid->len;

    if ((end - *p) < 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME,
                                 CUSTOM_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != CUSTOM_ASN1_BMP_STRING && **p != CUSTOM_ASN1_UTF8_STRING      &&
        **p != CUSTOM_ASN1_T61_STRING && **p != CUSTOM_ASN1_PRINTABLE_STRING &&
        **p != CUSTOM_ASN1_IA5_STRING && **p != CUSTOM_ASN1_UNIVERSAL_STRING &&
        **p != CUSTOM_ASN1_BIT_STRING) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME,
                                 CUSTOM_ERR_ASN1_UNEXPECTED_TAG);
    }

    val = &cur->val;
    val->tag = *(*p)++;

    if ((ret = custom_asn1_get_len(p, end, &val->len)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME, ret);
    }

    val->p = *p;
    *p += val->len;

    if (*p != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    cur->next = NULL;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("x509_get_attr_type_value - cur->oid", cur->oid.p, cur->oid.len);
    printf("x509_get_attr_type_value - cur->oid_tag = %02x\n", cur->oid.tag);
    print_hex_string("x509_get_attr_type_value - cur->val", cur->val.p, cur->val.len);
    printf("x509_get_attr_type_value - cur->val = %02x\n", cur->val.tag);
    printf("x509_get_attr_type_value - cur->val_next = %p\n", cur->next);
    #endif

    return 0;
}

int custom_x509_get_name(unsigned char **p, const unsigned char *end,
                          custom_x509_name *cur)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len;
    const unsigned char *end_set;
    custom_x509_name *head = cur;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while (1) {
        /*
         * parse SET
         */
        if ((ret = custom_asn1_get_tag(p, end, &set_len,
                                        CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SET)) != 0) {
            ret = CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_NAME, ret);
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

            /* Mark this item as being no the only one in a set */
            cur->next_merged = 1;

            cur->next = custom_calloc(1, sizeof(custom_x509_name));

            if (cur->next == NULL) {
                ret = CUSTOM_ERR_X509_ALLOC_FAILED;
                goto error;
            }

            #if CUSTOM_DEBUG_PRINTS
            printf("custom_x509_get_name - calloc: %lu\n", sizeof(custom_x509_name));
            #endif
            cur = cur->next;
        }

        /*
         * continue until end of SEQUENCE is reached
         */
        if (*p == end) {
            #if CUSTOM_DEBUG_PRINTS
            print_hex_string("custom_x509_get_name - cur->oid", cur->oid.p, cur->oid.len);
            printf("custom_x509_get_name - cur->oid_tag = %02x\n", cur->oid.tag);
            print_hex_string("custom_x509_get_name - cur->val", cur->val.p, cur->val.len);
            printf("custom_x509_get_name - cur->val = %02x\n", cur->val.tag);
            printf("custom_x509_get_name - cur->val_next = %p\n", cur->next);
            #endif
            return 0;
        }

        cur->next = custom_calloc(1, sizeof(custom_x509_name));

        if (cur->next == NULL) {
            ret = CUSTOM_ERR_X509_ALLOC_FAILED;
            goto error;
        }

        #if CUSTOM_DEBUG_PRINTS
        printf("custom_x509_get_name - calloc: %lu\n", sizeof(custom_x509_name));
        #endif
        cur = cur->next;
    }

error:
    /* Skip the first element as we did not allocate it */
    custom_asn1_free_named_data_list_shallow(head->next);
    head->next = NULL;

    return ret;
}

static int x509_parse_int(unsigned char **p, size_t n, int *res)
{
    *res = 0;

    for (; n > 0; --n) {
        if ((**p < '0') || (**p > '9')) {
            return CUSTOM_ERR_X509_INVALID_DATE;
        }

        *res *= 10;
        *res += (*(*p)++ - '0');
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("x509_parse_int - int: %d\n", *res);
    #endif
    return 0;
}

static int x509_date_is_valid(const custom_x509_time *t)
{
    int ret = CUSTOM_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE(0, 9999, t->year);
    CHECK_RANGE(0, 23,   t->hour);
    CHECK_RANGE(0, 59,   t->min);
    CHECK_RANGE(0, 59,   t->sec);

    switch (t->mon) {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if ((!(t->year % 4) && t->year % 100) ||
                !(t->year % 400)) {
                month_len = 29;
            } else {
                month_len = 28;
            }
            break;
        default:
            return ret;
    }
    CHECK_RANGE(1, month_len, t->day);

    return 0;
}

static int x509_parse_time(unsigned char **p, size_t len, size_t yearlen,
                           custom_x509_time *tm)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if (len < yearlen + 8) {
        return CUSTOM_ERR_X509_INVALID_DATE;
    }
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK(x509_parse_int(p, yearlen, &tm->year));
    if (2 == yearlen) {
        if (tm->year < 50) {
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
    if (len >= 2) {
        CHECK(x509_parse_int(p, 2, &tm->sec));
        len -= 2;
    } else {
        return CUSTOM_ERR_X509_INVALID_DATE;
    }

    /*
     * Parse trailing 'Z' if present
     */
    if (1 == len && 'Z' == **p) {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if (0 != len) {
        return CUSTOM_ERR_X509_INVALID_DATE;
    }

    CHECK(x509_date_is_valid(tm));

    #if CUSTOM_DEBUG_PRINTS
    printf("x509_parse_time - tm\n- year: %d, mon: %d, day: %d\n- hour: %d, min: %d, sec: %d\n", 
        tm->year, tm->mon, tm->day, tm->hour, tm->min, tm->sec);
    #endif
    return 0;
}

int custom_x509_get_time(unsigned char **p, const unsigned char *end,
                          custom_x509_time *tm)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len, year_len;
    unsigned char tag;

    if ((end - *p) < 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_DATE,
                                 CUSTOM_ERR_ASN1_OUT_OF_DATA);
    }

    tag = **p;

    if (tag == CUSTOM_ASN1_UTC_TIME) {
        year_len = 2;
    } else if (tag == CUSTOM_ASN1_GENERALIZED_TIME) {
        year_len = 4;
    } else {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_DATE,
                                 CUSTOM_ERR_ASN1_UNEXPECTED_TAG);
    }

    (*p)++;
    ret = custom_asn1_get_len(p, end, &len);

    if (ret != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_DATE, ret);
    }

    return x509_parse_time(p, len, year_len, tm);
}

int custom_x509_get_sig(unsigned char **p, const unsigned char *end, custom_x509_buf *sig)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    int tag_type;

    if ((end - *p) < 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_SIGNATURE,
                                 CUSTOM_ERR_ASN1_OUT_OF_DATA);
    }

    tag_type = **p;

    if ((ret = custom_asn1_get_bitstring_null(p, end, &len)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_SIGNATURE, ret);
    }

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    *p += len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_sig - sig", sig->p, sig->len);
    printf("custom_x509_get_sig - sig_tag = %02x\n", sig->tag);
    #endif
    return 0;
}

int custom_x509_get_sig_alg(const custom_x509_buf *sig_oid, const custom_x509_buf *sig_params,
                             custom_md_type_t *md_alg, custom_pk_type_t *pk_alg,
                             void **sig_opts) // new_impl
{
    // int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL) {
        return CUSTOM_ERR_X509_BAD_INPUT_DATA;
    }

    *pk_alg = CUSTOM_PK_ED25519;
    *md_alg = CUSTOM_MD_KEYSTONE_SHA3;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_get_sig_alg\n");
    #endif
    return 0;
}

int custom_x509_get_ext(unsigned char **p, const unsigned char *end,
                         custom_x509_buf *ext, int tag)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /* Extension structure use EXPLICIT tagging. That is, the actual
     * `Extensions` structure is wrapped by a tag-length pair using
     * the respective context-specific tag. */
    ret = custom_asn1_get_tag(p, end, &ext->len,
                               CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_ASN1_CONSTRUCTED | tag);
    if (ret != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    ext->tag = CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_ASN1_CONSTRUCTED | tag;
    ext->p   = *p;
    end      = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    if ((ret = custom_asn1_get_tag(p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (end != *p + len) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_ext - ext", ext->p, ext->len);
    printf("custom_x509_get_ext - ext_tag = %02x\n", ext->tag);
    #endif
    return 0;
}

#if defined(CUSTOM_HAVE_TIME_DATE)

static int x509_get_current_time(custom_x509_time *now)
{
    struct tm *lt, tm_buf;
    custom_time_t tt;
    int ret = 0;

    tt = custom_time(NULL);
    lt = custom_platform_gmtime_r(&tt, &tm_buf);

    if (lt == NULL) {
        ret = -1;
    } else {
        now->year = lt->tm_year + 1900;
        now->mon  = lt->tm_mon  + 1;
        now->day  = lt->tm_mday;
        now->hour = lt->tm_hour;
        now->min  = lt->tm_min;
        now->sec  = lt->tm_sec;
    }

    return ret;
}

static int x509_check_time(const custom_x509_time *before, const custom_x509_time *after)
{
    if (before->year  > after->year) {
        return 1;
    }

    if (before->year == after->year &&
        before->mon   > after->mon) {
        return 1;
    }

    if (before->year == after->year &&
        before->mon  == after->mon  &&
        before->day   > after->day) {
        return 1;
    }

    if (before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour  > after->hour) {
        return 1;
    }

    if (before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min   > after->min) {
        return 1;
    }

    if (before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min  == after->min  &&
        before->sec   > after->sec) {
        return 1;
    }

    return 0;
}

int custom_x509_time_is_past(const custom_x509_time *to)
{
    custom_x509_time now;

    if (x509_get_current_time(&now) != 0) {
        return 1;
    }

    return x509_check_time(&now, to);
}

int custom_x509_time_is_future(const custom_x509_time *from)
{
    custom_x509_time now;

    if (x509_get_current_time(&now) != 0) {
        return 1;
    }

    return x509_check_time(from, &now);
}

#else  /* CUSTOM_HAVE_TIME_DATE */

int custom_x509_time_is_past(const custom_x509_time *to)
{
    ((void) to);
    return 0;
}

int custom_x509_time_is_future(const custom_x509_time *from)
{
    ((void) from);
    return 0;
}
#endif /* CUSTOM_HAVE_TIME_DATE */

static int x509_get_other_name(const custom_x509_buf *subject_alt_name,
                               custom_x509_san_other_name *other_name)
{
    int ret = 0;
    size_t len;
    unsigned char *p = subject_alt_name->p;
    const unsigned char *end = p + subject_alt_name->len;
    custom_x509_buf cur_oid;

    if ((subject_alt_name->tag &
         (CUSTOM_ASN1_TAG_CLASS_MASK | CUSTOM_ASN1_TAG_VALUE_MASK)) !=
        (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_OTHER_NAME)) {
        /*
         * The given subject alternative name is not of type "othername".
         */
        return CUSTOM_ERR_X509_BAD_INPUT_DATA;
    }

    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_OID)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    cur_oid.tag = CUSTOM_ASN1_OID;
    cur_oid.p = p;
    cur_oid.len = len;

    /*
     * Only HwModuleName is currently supported.
     */
    if (CUSTOM_OID_CMP(CUSTOM_OID_ON_HW_MODULE_NAME, &cur_oid) != 0) {
        return CUSTOM_ERR_X509_FEATURE_UNAVAILABLE;
    }

    p += len;
    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_CONTEXT_SPECIFIC)) !=
        0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (end != p + len) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (end != p + len) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((ret = custom_asn1_get_tag(&p, end, &len, CUSTOM_ASN1_OID)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    other_name->value.hardware_module_name.oid.tag = CUSTOM_ASN1_OID;
    other_name->value.hardware_module_name.oid.p = p;
    other_name->value.hardware_module_name.oid.len = len;

    p += len;
    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_OCTET_STRING)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    other_name->value.hardware_module_name.val.tag = CUSTOM_ASN1_OCTET_STRING;
    other_name->value.hardware_module_name.val.p = p;
    other_name->value.hardware_module_name.val.len = len;
    p += len;
    if (p != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}

int custom_x509_get_subject_alt_name(unsigned char **p,
                                      const unsigned char *end,
                                      custom_x509_sequence *subject_alt_name)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len, tag_len;
    custom_asn1_sequence *cur = subject_alt_name;

    /* Get main sequence tag */
    if ((ret = custom_asn1_get_tag(p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p + len != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    while (*p < end) {
        custom_x509_subject_alternative_name dumcustom_san_buf;
        custom_x509_buf tmp_san_buf;
        custom_memset(&dumcustom_san_buf, 0, sizeof(dumcustom_san_buf));

        tmp_san_buf.tag = **p;
        (*p)++;

        if ((ret = custom_asn1_get_len(p, end, &tag_len)) != 0) {
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        tmp_san_buf.p = *p;
        tmp_san_buf.len = tag_len;

        if ((tmp_san_buf.tag & CUSTOM_ASN1_TAG_CLASS_MASK) !=
            CUSTOM_ASN1_CONTEXT_SPECIFIC) {
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                     CUSTOM_ERR_ASN1_UNEXPECTED_TAG);
        }

        /*
         * Check that the SAN is structured correctly.
         */
        ret = custom_x509_parse_subject_alt_name(&tmp_san_buf, &dumcustom_san_buf);
        /*
         * In case the extension is malformed, return an error,
         * and clear the allocated sequences.
         */
        if (ret != 0 && ret != CUSTOM_ERR_X509_FEATURE_UNAVAILABLE) {
            custom_asn1_sequence_free(subject_alt_name->next);
            subject_alt_name->next = NULL;
            return ret;
        }

        custom_x509_free_subject_alt_name(&dumcustom_san_buf);
        /* Allocate and assign next pointer */
        if (cur->buf.p != NULL) {
            if (cur->next != NULL) {
                return CUSTOM_ERR_X509_INVALID_EXTENSIONS;
            }

            cur->next = custom_calloc(1, sizeof(custom_asn1_sequence));

            if (cur->next == NULL) {
                return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                         CUSTOM_ERR_ASN1_ALLOC_FAILED);
            }

            #if CUSTOM_DEBUG_PRINTS
            printf("custom_x509_get_subject_alt_name - calloc: %lu\n", sizeof(custom_asn1_sequence));
            #endif

            cur = cur->next;
        }

        cur->buf = tmp_san_buf;
        *p += tmp_san_buf.len;
    }

    /* Set final sequence entry's next pointer to NULL */
    cur->next = NULL;

    if (*p != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int custom_x509_get_ns_cert_type(unsigned char **p,
                                  const unsigned char *end,
                                  unsigned char *ns_cert_type)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    custom_x509_bitstring bs = { 0, 0, NULL };

    if ((ret = custom_asn1_get_bitstring(p, end, &bs)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    /* A bitstring with no flags set is still technically valid, as it will mean
       that the certificate has no designated purpose at the time of creation. */
    if (bs.len == 0) {
        *ns_cert_type = 0;
        return 0;
    }

    if (bs.len != 1) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_INVALID_LENGTH);
    }

    /* Get actual bitstring */
    *ns_cert_type = *bs.p;
    return 0;
}

int custom_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    custom_x509_bitstring bs = { 0, 0, NULL };

    if ((ret = custom_asn1_get_bitstring(p, end, &bs)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    /* A bitstring with no flags set is still technically valid, as it will mean
       that the certificate has no designated purpose at the time of creation. */
    if (bs.len == 0) {
        *key_usage = 0;
        return 0;
    }

    /* Get actual bitstring */
    *key_usage = 0;
    for (i = 0; i < bs.len && i < sizeof(unsigned int); i++) {
        *key_usage |= (unsigned int) bs.p[i] << (8*i);
    }

    return 0;
}

int custom_x509_parse_subject_alt_name(const custom_x509_buf *san_buf,
                                        custom_x509_subject_alternative_name *san)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    switch (san_buf->tag &
            (CUSTOM_ASN1_TAG_CLASS_MASK |
             CUSTOM_ASN1_TAG_VALUE_MASK)) {
        /*
         * otherName
         */
        case (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_OTHER_NAME):
        {
            custom_x509_san_other_name other_name;

            ret = x509_get_other_name(san_buf, &other_name);
            if (ret != 0) {
                return ret;
            }

            custom_memset(san, 0, sizeof(custom_x509_subject_alternative_name));
            san->type = CUSTOM_X509_SAN_OTHER_NAME;
            custom_memcpy(&san->san.other_name,
                   &other_name, sizeof(other_name));

        }
        break;
        /*
         * uniformResourceIdentifier
         */
        case (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER):
        {
            custom_memset(san, 0, sizeof(custom_x509_subject_alternative_name));
            san->type = CUSTOM_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER;

            custom_memcpy(&san->san.unstructured_name,
                   san_buf, sizeof(*san_buf));

        }
        break;
        /*
         * dNSName
         */
        case (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_DNS_NAME):
        {
            custom_memset(san, 0, sizeof(custom_x509_subject_alternative_name));
            san->type = CUSTOM_X509_SAN_DNS_NAME;

            custom_memcpy(&san->san.unstructured_name,
                   san_buf, sizeof(*san_buf));
        }
        break;

        /*
         * RFC822 Name
         */
        case (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_RFC822_NAME):
        {
            custom_memset(san, 0, sizeof(custom_x509_subject_alternative_name));
            san->type = CUSTOM_X509_SAN_RFC822_NAME;
            custom_memcpy(&san->san.unstructured_name, san_buf, sizeof(*san_buf));
        }
        break;

        /*
         * directoryName
         */
        case (CUSTOM_ASN1_CONTEXT_SPECIFIC | CUSTOM_X509_SAN_DIRECTORY_NAME):
        {
            size_t name_len;
            unsigned char *p = san_buf->p;
            custom_memset(san, 0, sizeof(custom_x509_subject_alternative_name));
            san->type = CUSTOM_X509_SAN_DIRECTORY_NAME;

            ret = custom_asn1_get_tag(&p, p + san_buf->len, &name_len,
                                       CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE);

            if (ret != 0) {
                return ret;
            }

            if ((ret = custom_x509_get_name(&p, p + name_len,
                                             &san->san.directory_name)) != 0) {
                return ret;
            }
        }
        break;
        /*
         * Type not supported
         */
        default:
            return CUSTOM_ERR_X509_FEATURE_UNAVAILABLE;
    }
    return 0;
}

void custom_x509_free_subject_alt_name(custom_x509_subject_alternative_name *san)
{
    if (san->type == CUSTOM_X509_SAN_DIRECTORY_NAME) {
        custom_asn1_free_named_data_list_shallow(san->san.directory_name.next);
    }
}

// x509_create.c
#define ADD_STRLEN(s)     s, sizeof(s) - 1

/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct {
    const char *name; /* String representation of AttributeType, e.g.
                       * "CN" or "emailAddress". */
    size_t name_len; /* Length of 'name', without trailing 0 byte. */
    const char *oid; /* String representation of OID of AttributeType,
                      * as per RFC 5280, Appendix A.1. */
    int default_tag; /* The default character encoding used for the
                      * given attribute type, e.g.
                      * CUSTOM_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;

/* X.509 DN attributes from RFC 5280, Appendix A.1. */
static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN("CN"),
      CUSTOM_OID_AT_CN, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("commonName"),
      CUSTOM_OID_AT_CN, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("C"),
      CUSTOM_OID_AT_COUNTRY, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("countryName"),
      CUSTOM_OID_AT_COUNTRY, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("O"),
      CUSTOM_OID_AT_ORGANIZATION, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationName"),
      CUSTOM_OID_AT_ORGANIZATION, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("L"),
      CUSTOM_OID_AT_LOCALITY, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("locality"),
      CUSTOM_OID_AT_LOCALITY, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("R"),
      CUSTOM_OID_PKCS9_EMAIL, CUSTOM_ASN1_IA5_STRING },
    { ADD_STRLEN("OU"),
      CUSTOM_OID_AT_ORG_UNIT, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationalUnitName"),
      CUSTOM_OID_AT_ORG_UNIT, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("ST"),
      CUSTOM_OID_AT_STATE, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("stateOrProvinceName"),
      CUSTOM_OID_AT_STATE, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("emailAddress"),
      CUSTOM_OID_PKCS9_EMAIL, CUSTOM_ASN1_IA5_STRING },
    { ADD_STRLEN("serialNumber"),
      CUSTOM_OID_AT_SERIAL_NUMBER, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalAddress"),
      CUSTOM_OID_AT_POSTAL_ADDRESS, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalCode"),
      CUSTOM_OID_AT_POSTAL_CODE, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("dnQualifier"),
      CUSTOM_OID_AT_DN_QUALIFIER, CUSTOM_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("title"),
      CUSTOM_OID_AT_TITLE, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("surName"),
      CUSTOM_OID_AT_SUR_NAME, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("SN"),
      CUSTOM_OID_AT_SUR_NAME, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("givenName"),
      CUSTOM_OID_AT_GIVEN_NAME, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("GN"),
      CUSTOM_OID_AT_GIVEN_NAME, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("initials"),
      CUSTOM_OID_AT_INITIALS, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("pseudonym"),
      CUSTOM_OID_AT_PSEUDONYM, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("generationQualifier"),
      CUSTOM_OID_AT_GENERATION_QUALIFIER, CUSTOM_ASN1_UTF8_STRING },
    { ADD_STRLEN("domainComponent"),
      CUSTOM_OID_DOMAIN_COMPONENT, CUSTOM_ASN1_IA5_STRING },
    { ADD_STRLEN("DC"),
      CUSTOM_OID_DOMAIN_COMPONENT,   CUSTOM_ASN1_IA5_STRING },
    { NULL, 0, NULL, CUSTOM_ASN1_NULL }
};

static const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++) {
        if (cur->name_len == name_len &&
            custom_strncmp(cur->name, name, name_len) == 0) {
            break;
        }
    }

    if (cur->name == NULL) {
        return NULL;
    }

    return cur;
}

int custom_x509_string_to_names(custom_asn1_named_data **head, const char *name)
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + custom_strlen(s);
    const char *oid = NULL;
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_tag = 1;
    char data[CUSTOM_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_string_to_names - name: %s\n", name);
    #endif
    /* Clear existing chain if present */
    custom_asn1_free_named_data_list(head);

    while (c <= end) {
        if (in_tag && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, c - s)) == NULL) {
                ret = CUSTOM_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end) {
            c++;

            /* Check for valid escaped characters */
            if (c == end || *c != ',') {
                ret = CUSTOM_ERR_X509_INVALID_NAME;
                goto exit;
            }
        } else if (!in_tag && (*c == ',' || c == end)) {
            custom_asn1_named_data *cur =
                custom_asn1_store_named_data(head, oid, custom_strlen(oid),
                                              (unsigned char *) data,
                                              d - data);

            if (cur == NULL) {
                return CUSTOM_ERR_X509_ALLOC_FAILED;
            }

            // set tagType
            cur->val.tag = attr_descr->default_tag;

            #if CUSTOM_DEBUG_PRINTS
            printf("stored:\n- oid: %s\n- oid_len: %d\n- data: %s\n- data_len: %d\n", cur->oid.p, cur->oid.len, cur->val.p, cur->val.len);
            #endif
            while (c < end && *(c + 1) == ' ') {
                c++;
            }

            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1) {
            *(d++) = *c;

            if (d - data == CUSTOM_X509_MAX_DN_NAME_SIZE) {
                ret = CUSTOM_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return ret;
}

int custom_x509_set_extension(custom_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val, size_t val_len)
{
    custom_asn1_named_data *cur;

    if ((cur = custom_asn1_store_named_data(head, oid, oid_len,
                                             NULL, val_len + 1)) == NULL) {
        return CUSTOM_ERR_X509_ALLOC_FAILED;
    }

    cur->val.p[0] = critical;
    custom_memcpy(cur->val.p + 1, val, val_len);

    return 0;
}

static int x509_write_name(unsigned char **p,
                           unsigned char *start,
                           custom_asn1_named_data *cur_name)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid             = (const char *) cur_name->oid.p;
    size_t oid_len              = cur_name->oid.len;
    const unsigned char *name   = cur_name->val.p;
    size_t name_len             = cur_name->val.len;

    // Write correct string tag and value
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tagged_string(p, start,
                                                               cur_name->val.tag,
                                                               (const char *) name,
                                                               name_len));
    // Write OID
    //
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_oid(p, start, oid,
                                                     oid_len));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start,
                                                     CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SEQUENCE));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start,
                                                     CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SET));

    #if CUSTOM_DEBUG_PRINTS
    printf("x509_write_name - len = %d\n", len);
    #endif
    return (int) len;
}

int custom_x509_write_names(unsigned char **p, unsigned char *start,
                             custom_asn1_named_data *first)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    custom_asn1_named_data *cur = first;

    while (cur != NULL) {
        CUSTOM_ASN1_CHK_ADD(len, x509_write_name(p, start, cur));
        cur = cur->next;
    }

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SEQUENCE));

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_write_names - len = %d\n", len);
    #endif
    return (int) len;
}

int custom_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    custom_memcpy(*p, sig, len);

    if (*p - start < 1) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = 0;
    len += 1;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_BIT_STRING));

    // Write OID
    //
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_algorithm_identifier(p, start, oid,
                                                                      oid_len, 0));

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_write_sig - len = %d\n", len);
    #endif
    return (int) len;
}

static int x509_write_extension(unsigned char **p, unsigned char *start,
                                custom_asn1_named_data *ext)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(p, start, ext->val.p + 1,
                                                            ext->val.len - 1));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, ext->val.len - 1));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_OCTET_STRING));

    if (ext->val.p[0] != 0) {
        CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_bool(p, start, 1));
    }

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(p, start, ext->oid.p,
                                                            ext->oid.len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, ext->oid.len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_OID));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start, CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SEQUENCE));

    #if CUSTOM_DEBUG_PRINTS
    printf("x509_write_extension - len = %d\n", len);
    #endif
    return (int) len;
}

int custom_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  custom_asn1_named_data *first)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    custom_asn1_named_data *cur_ext = first;

    while (cur_ext != NULL) {
        CUSTOM_ASN1_CHK_ADD(len, x509_write_extension(p, start, cur_ext));
        #if CUSTOM_DEBUG_PRINTS
        print_custom_asn1_named_data("custom_x509_write_extensions", *cur_ext);
        #endif
        cur_ext = cur_ext->next;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_write_extensions - len = %d\n", len);
    #endif
    return (int) len;
}
