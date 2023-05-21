// x509.c
#define CHECK(code)          \
    if ((ret = (code)) != 0) \
    {                        \
        return ret;          \
    }
#define CHECK_RANGE(min, max, val)          \
    do                                      \
    {                                       \
        if ((val) < (min) || (val) > (max)) \
        {                                   \
            return ret;                     \
        }                                   \
    } while (0)

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

// x509_create.c
#define ADD_STRLEN(s) s, sizeof(s) - 1

/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct
{
    const char *name; /* String representation of AttributeType, e.g.
                       * "CN" or "emailAddress". */
    size_t name_len;  /* Length of 'name', without trailing 0 byte. */
    const char *oid;  /* String representation of OID of AttributeType,
                       * as per RFC 5280, Appendix A.1. */
    int default_tag;  /* The default character encoding used for the
                       * given attribute type, e.g.
                       * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;

/* X.509 DN attributes from RFC 5280, Appendix A.1. */
static const x509_attr_descriptor_t x509_attrs[] =
    {
        {ADD_STRLEN("CN"),
         MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("commonName"),
         MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("C"),
         MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("countryName"),
         MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("O"),
         MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("organizationName"),
         MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("L"),
         MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("locality"),
         MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("R"),
         MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING},
        {ADD_STRLEN("OU"),
         MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("organizationalUnitName"),
         MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("ST"),
         MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("stateOrProvinceName"),
         MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("emailAddress"),
         MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING},
        {ADD_STRLEN("serialNumber"),
         MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("postalAddress"),
         MBEDTLS_OID_AT_POSTAL_ADDRESS, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("postalCode"),
         MBEDTLS_OID_AT_POSTAL_CODE, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("dnQualifier"),
         MBEDTLS_OID_AT_DN_QUALIFIER, MBEDTLS_ASN1_PRINTABLE_STRING},
        {ADD_STRLEN("title"),
         MBEDTLS_OID_AT_TITLE, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("surName"),
         MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("SN"),
         MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("givenName"),
         MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("GN"),
         MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("initials"),
         MBEDTLS_OID_AT_INITIALS, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("pseudonym"),
         MBEDTLS_OID_AT_PSEUDONYM, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("generationQualifier"),
         MBEDTLS_OID_AT_GENERATION_QUALIFIER, MBEDTLS_ASN1_UTF8_STRING},
        {ADD_STRLEN("domainComponent"),
         MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING},
        {ADD_STRLEN("DC"),
         MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING},
        {NULL, 0, NULL, MBEDTLS_ASN1_NULL}};

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