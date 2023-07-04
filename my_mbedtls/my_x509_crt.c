#include "custom_functions.h"
#include "sha3.h"
#include "ed25519/ed25519.h"

// x509_crt.c

const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_keystone =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_KEYSTONE_SHA3),
    MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ED25519),
    0,
    2048, // not supported
};

static int x509_profile_check_md_alg(const mbedtls_x509_crt_profile *profile,
                                     mbedtls_md_type_t md_alg)
{
    if (md_alg == MBEDTLS_MD_NONE) {
        return -1;
    }

    if ((profile->allowed_mds & MBEDTLS_X509_ID_FLAG(md_alg)) != 0) {
        return 0;
    }

    return -1;
}

static int x509_profile_check_pk_alg(const mbedtls_x509_crt_profile *profile,
                                     mbedtls_pk_type_t pk_alg)
{
    if (pk_alg == MBEDTLS_PK_NONE) {
        return -1;
    }

    if ((profile->allowed_pks & MBEDTLS_X509_ID_FLAG(pk_alg)) != 0) {
        return 0;
    }

    return -1;
}

static int x509_profile_check_key(const mbedtls_x509_crt_profile *profile,
                                  const mbedtls_pk_context *pk)
{
    const mbedtls_pk_type_t pk_alg = mbedtls_pk_get_type(pk);

    return x509_profile_check_pk_alg(profile, pk_alg);
}

static int x509_memcasecmp(const void *s1, const void *s2, size_t len)
{
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    for (i = 0; i < len; i++) {
        diff = n1[i] ^ n2[i];

        if (diff == 0) {
            continue;
        }

        if (diff == 32 &&
            ((n1[i] >= 'a' && n1[i] <= 'z') ||
             (n1[i] >= 'A' && n1[i] <= 'Z'))) {
            continue;
        }

        return -1;
    }

    return 0;
}

static int x509_check_wildcard(const char *cn, const mbedtls_x509_buf *name)
{
    size_t i;
    size_t cn_idx = 0, cn_len = my_strlen(cn);

    /* We can't have a match if there is no wildcard to match */
    if (name->len < 3 || name->p[0] != '*' || name->p[1] != '.') {
        return -1;
    }

    for (i = 0; i < cn_len; ++i) {
        if (cn[i] == '.') {
            cn_idx = i;
            break;
        }
    }

    if (cn_idx == 0) {
        return -1;
    }

    if (cn_len - cn_idx == name->len - 1 &&
        x509_memcasecmp(name->p + 1, cn + cn_idx, name->len - 1) == 0) {
        return 0;
    }

    return -1;
}

static int x509_string_cmp(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
    if (a->tag == b->tag &&
        a->len == b->len &&
        my_memcmp(a->p, b->p, b->len) == 0) {
        return 0;
    }

    if ((a->tag == MBEDTLS_ASN1_UTF8_STRING || a->tag == MBEDTLS_ASN1_PRINTABLE_STRING) &&
        (b->tag == MBEDTLS_ASN1_UTF8_STRING || b->tag == MBEDTLS_ASN1_PRINTABLE_STRING) &&
        a->len == b->len &&
        x509_memcasecmp(a->p, b->p, b->len) == 0) {
        return 0;
    }

    return -1;
}

static int x509_name_cmp(const mbedtls_x509_name *a, const mbedtls_x509_name *b)
{
    /* Avoid recursion, it might not be optimised by the compiler */
    while (a != NULL || b != NULL) {
        if (a == NULL || b == NULL) {
            return -1;
        }

        /* type */
        if (a->oid.tag != b->oid.tag ||
            a->oid.len != b->oid.len ||
            my_memcmp(a->oid.p, b->oid.p, b->oid.len) != 0) {
            return -1;
        }

        /* value */
        if (x509_string_cmp(&a->val, &b->val) != 0) {
            return -1;
        }

        /* structure of the list of sets */
        if (a->next_merged != b->next_merged) {
            return -1;
        }

        a = a->next;
        b = b->next;
    }

    /* a == NULL == b */
    return 0;
}

static void x509_crt_verify_chain_reset(
    mbedtls_x509_crt_verify_chain *ver_chain)
{
    size_t i;

    for (i = 0; i < MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE; i++) {
        ver_chain->items[i].crt = NULL;
        ver_chain->items[i].flags = (uint32_t) -1;
    }

    ver_chain->len = 0;

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    ver_chain->trust_ca_cb_result = NULL;
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
}

static int x509_get_version(unsigned char **p,
                            const unsigned char *end,
                            int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    0)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            *ver = 0;
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_asn1_get_int(p, end, ver)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION, ret);
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_get_version - int = %d\n", *ver);
    #endif
    return 0;
}

static int x509_get_dates(unsigned char **p,
                          const unsigned char *end,
                          mbedtls_x509_time *from,
                          mbedtls_x509_time *to)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_x509_get_time(p, end, from)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_x509_get_time(p, end, to)) != 0) {
        return ret;
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_get_dates - from\n- year: %d, mon: %d, day: %d\n- hour: %d, min: %d, sec: %d\n", 
        from->year, from->mon, from->day, from->hour, from->min, from->sec);
    my_printf("x509_get_dates - to\n- year: %d, mon: %d, day: %d\n- hour: %d, min: %d, sec: %d\n", 
        to->year, to->mon, to->day, to->hour, to->min, to->sec);
    #endif
    return 0;
}

static int x509_get_uid(unsigned char **p,
                        const unsigned char *end,
                        mbedtls_x509_buf *uid, int n)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*p == end) {
        return 0;
    }

    uid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &uid->len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    n)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    uid->p = *p;
    *p += uid->len;

    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("x509_get_uid - uid", uid->p, uid->len);
    my_printf("x509_get_uid - uid_tag = %02x\n", uid->tag);
    #endif
    return 0;
}

static int x509_get_basic_constraints(unsigned char **p,
                                      const unsigned char *end,
                                      int *ca_istrue,
                                      int *max_pathlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /*
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    *ca_istrue = 0; /* DEFAULT FALSE */
    *max_pathlen = 0; /* endless */

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_bool(p, end, ca_istrue)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            ret = mbedtls_asn1_get_int(p, end, ca_istrue);
        }

        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        if (*ca_istrue != 0) {
            *ca_istrue = 1;
        }
    }

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_int(p, end, max_pathlen)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    /* Do not accept max_pathlen equal to INT_MAX to avoid a signed integer
     * overflow, which is an undefined behavior. */
    if (*max_pathlen == INT_MAX) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    (*max_pathlen)++;

    return 0;
}

static int x509_get_crt_ext(unsigned char **p,
                            const unsigned char *end,
                            mbedtls_x509_crt *crt,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data /**start_ext_octet*/, *end_ext_octet;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_get_crt_ext\n");
    #endif

    // unsigned char oid_ext1[] = {0xff, 0x20, 0xff};
    unsigned char oid_ext2[] = {0x55, 0x1d, 0x13};

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
        return ret;
    }

    end = crt->v3_ext.p + crt->v3_ext.len;
    while (*p < end) {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int is_critical = 0; /* DEFAULT FALSE */
        // int ext_type = 0;

        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        // start_ext_octet = *p;
        end_ext_octet = *p + len;

        if (end_ext_octet != end_ext_data) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }
        
        if(my_memcmp(extn_oid.p, oid_ext2, 3)== 0){
            //crt->ca_istrue = 1;
            //unsigned char app = **p;
            //crt->max_pathlen = (int) app;
            //crt->max_pathlen = (*p);
            //*p +=1;
            if ((ret = x509_get_basic_constraints(p, end_ext_octet,
                                                      &crt->ca_istrue, &crt->max_pathlen)) != 0) {
                  
                   return ret;
                }
        }
        else{
            crt ->hash.p = *p;
            crt ->hash.len = 64;
            *p += 64;
        }


        // my_memcpy(crt->hash.p_arr,*p, 64);

        // crt->hash.p = *p;
        // crt->hash.len = 64;
        // *p += 64;

        /*
         * Detect supported extensions
         */
        // ret = mbedtls_oid_get_x509_ext_type(&extn_oid, &ext_type);

        // if (ret != 0) {
        /* Give the callback (if any) a chance to handle the extension */
        //   if (cb != NULL) {
        //     ret = cb(p_ctx, crt, &extn_oid, is_critical, *p, end_ext_octet);
        //   if (ret != 0 && is_critical) {
        //     return ret;
        //}
        //*p = end_ext_octet;
        // continue;
        //}

        /* No parser found, skip extension */
        //*p = end_ext_octet;

        // if (is_critical) {
        /* Data is marked as critical: fail */
        //  return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
        // MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
        //}
        // continue;
        //}

        /* Forbid repeated extensions */
        // if ((crt->ext_types & ext_type) != 0) {
        //   return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        //}

        // crt->ext_types |= ext_type;

        /**
         * Le extensions non vengono parsate come un array di tali, ma vanno direttamente a fillare il
         * campo corrrispettivo nella struttura
         *
         */
        // switch (ext_type) {
        /*
        case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
            // Parse basic constraints
            if ((ret = x509_get_basic_constraints(p, end_ext_octet,
                                                  &crt->ca_istrue, &crt->max_pathlen)) != 0) {
                return ret;
            }
            break;
        case MBEDTLS_X509_EXT_KEY_USAGE:
            // Parse key usage
            if ((ret = mbedtls_x509_get_key_usage(p, end_ext_octet,
                                                  &crt->key_usage)) != 0) {
                return ret;
            }
            break;
        case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
            // Parse extended key usage
            if ((ret = x509_get_ext_key_usage(p, end_ext_octet,
                                              &crt->ext_key_usage)) != 0) {
                return ret;
            }
            break;
        case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
            // Parse subject alt name
            if ((ret = mbedtls_x509_get_subject_alt_name(p, end_ext_octet,
                                                         &crt->subject_alt_names)) != 0) {
                return ret;
            }
            break;
        case MBEDTLS_X509_EXT_NS_CERT_TYPE:
            // Parse netscape certificate type
            if ((ret = mbedtls_x509_get_ns_cert_type(p, end_ext_octet,
                                                     &crt->ns_cert_type)) != 0) {
                return ret;
            }
            break;
        case MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES:
            // Parse certificate policies type
            if ((ret = x509_get_certificate_policies(p, end_ext_octet,
                                                     &crt->certificate_policies)) != 0) {
                //Give the callback (if any) a chance to handle the extension
                 // if it contains unsupported policies
                if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE && cb != NULL &&
                    cb(p_ctx, crt, &extn_oid, is_critical,
                       start_ext_octet, end_ext_octet) == 0) {
                    break;
                }
                if (is_critical) {
                    return ret;
                } else
                //
                 // If MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE is returned, then we
                 // cannot interpret or enforce the policy. However, it is up to
                 // the user to choose how to enforce the policies,
                 // unless the extension is critical.
                 //
                if (ret != MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) {
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
        //  if (is_critical) {
        //    return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
        //} else {
        //  *p = end_ext_octet;
        //}
        //}
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

static int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                                   const unsigned char *buf,
                                   size_t buflen,
                                   int make_copy,
                                   mbedtls_x509_crt_ext_cb_t cb,
                                   void *p_ctx)
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
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    /* Use the original buffer until we figure out actual length. */
    p = (unsigned char *) buf;
    len = buflen;
    end = p + len;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - certificate\n");
    #endif
    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    end = crt_end = p + len;
    crt->raw.len = crt_end - buf;
    if (make_copy != 0) {
        /* Create and populate a new buffer for the raw field. */
        crt->raw.p = p = mbedtls_calloc(1, crt->raw.len);
        if (crt->raw.p == NULL) {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        #if MBEDTLS_DEBUG_PRINTS
        my_printf("x509_crt_parse_der_core - calloc: %lu\n", crt->raw.len);
        #endif
        my_memcpy(crt->raw.p, buf, crt->raw.len);
        crt->own_buffer = 1;

        p += crt->raw.len - len;
        end = crt_end = p + len;
    } else {
        crt->raw.p = (unsigned char *) buf;
        crt->own_buffer = 0;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - tbs cert\n");
    #endif
    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - version\n");
    #endif
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
                                    &sig_params1)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->version < 0 || crt->version > 2) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }

    crt->version++;

    if ((ret = mbedtls_x509_get_sig_alg(&crt->sig_oid, &sig_params1,
                                        &crt->sig_md, &crt->sig_pk,
                                        &crt->sig_opts)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - issuer\n");
    #endif
    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    if ((ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    crt->issuer_raw.len = p - crt->issuer_raw.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - validity\n");
    #endif
    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if ((ret = x509_get_dates(&p, end, &crt->valid_from,
                              &crt->valid_to)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - subject\n");
    #endif
    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    if (len && (ret = mbedtls_x509_get_name(&p, p + len, &crt->subject)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    crt->subject_raw.len = p - crt->subject_raw.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - subPKInfo\n");
    #endif
    /*
     * SubjectPublicKeyInfo
     */
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->pk_raw.len = p - crt->pk_raw.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - uid and exts\n");
    #endif
    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->issuer_id,  1);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->subject_id,  2);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (crt->version == 3) {
        ret = x509_get_crt_ext(&p, end, crt, cb, p_ctx);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }

    if (p != end) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    end = crt_end;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_crt_parse_der_core - signature\n");
    #endif
    /*
     *  }
     *  -- end of TBSCertificate
     *
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if ((ret = mbedtls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (crt->sig_oid.len != sig_oid2.len ||
        my_memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 ||
        sig_params1.tag != sig_params2.tag ||
        sig_params1.len != sig_params2.len ||
        (sig_params1.len != 0 &&
         my_memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0)) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_SIG_MISMATCH;
    }

    if ((ret = mbedtls_x509_get_sig(&p, end, &crt->sig)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }

    if (p != end) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
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
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    while (crt->version != 0 && crt->next != NULL) {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if (crt->version != 0 && crt->next == NULL) {
        crt->next = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));

        if (crt->next == NULL) {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }

        #if MBEDTLS_DEBUG_PRINTS
        my_printf("mbedtls_x509_crt_parse_der_internal - calloc: %lu\n", sizeof(mbedtls_x509_crt));
        #endif
        prev = crt;
        mbedtls_x509_crt_init(crt->next);
        crt = crt->next;
    }

    ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx);
    if (ret != 0) {
        if (prev) {
            prev->next = NULL;
        }

        if (crt != chain) {
            mbedtls_free(crt);
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("mbedtls_x509_crt_parse_der_internal - free: %lu\n", sizeof(mbedtls_x509_crt));
            #endif
        }

        return ret;
    }

    return 0;
}

int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 1, NULL, NULL);
}

int mbedtls_x509_crt_check_key_usage(const mbedtls_x509_crt *crt,
                                     unsigned int usage)
{
    unsigned int usage_must, usage_may;
    unsigned int may_mask = MBEDTLS_X509_KU_ENCIPHER_ONLY
                            | MBEDTLS_X509_KU_DECIPHER_ONLY;

    if ((crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0) {
        return 0;
    }

    usage_must = usage & ~may_mask;

    if (((crt->key_usage & ~may_mask) & usage_must) != usage_must) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    usage_may = usage & may_mask;

    if (((crt->key_usage & may_mask) | usage_may) != usage_may) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    return 0;
}

#if defined(MBEDTLS_X509_CRL_PARSE_C)

int mbedtls_x509_crt_is_revoked(const mbedtls_x509_crt *crt, const mbedtls_x509_crl *crl)
{
    const mbedtls_x509_crl_entry *cur = &crl->entry;

    while (cur != NULL && cur->serial.len != 0) {
        if (crt->serial.len == cur->serial.len &&
            memcmp(crt->serial.p, cur->serial.p, crt->serial.len) == 0) {
            return 1;
        }

        cur = cur->next;
    }

    return 0;
}

static int x509_crt_verifycrl(mbedtls_x509_crt *crt, mbedtls_x509_crt *ca,
                              mbedtls_x509_crl *crl_list,
                              const mbedtls_x509_crt_profile *profile)
{
    int flags = 0;
    unsigned char hash[MBEDTLS_HASH_MAX_SIZE];
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_algorithm_t psa_algorithm;
#else
    const mbedtls_md_info_t *md_info;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    size_t hash_length;

    if (ca == NULL) {
        return flags;
    }

    while (crl_list != NULL) {
        if (crl_list->version == 0 ||
            x509_name_cmp(&crl_list->issuer, &ca->subject) != 0) {
            crl_list = crl_list->next;
            continue;
        }

        /*
         * Check if the CA is configured to sign CRLs
         */
        if (mbedtls_x509_crt_check_key_usage(ca,
                                             MBEDTLS_X509_KU_CRL_SIGN) != 0) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check if CRL is correctly signed by the trusted CA
         */
        if (x509_profile_check_md_alg(profile, crl_list->sig_md) != 0) {
            flags |= MBEDTLS_X509_BADCRL_BAD_MD;
        }

        if (x509_profile_check_pk_alg(profile, crl_list->sig_pk) != 0) {
            flags |= MBEDTLS_X509_BADCRL_BAD_PK;
        }

#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_algorithm = mbedtls_hash_info_psa_from_md(crl_list->sig_md);
        if (psa_hash_compute(psa_algorithm,
                             crl_list->tbs.p,
                             crl_list->tbs.len,
                             hash,
                             sizeof(hash),
                             &hash_length) != PSA_SUCCESS) {
            /* Note: this can't happen except after an internal error */
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#else
        md_info = mbedtls_md_info_from_type(crl_list->sig_md);
        hash_length = mbedtls_md_get_size(md_info);
        if (mbedtls_md(md_info,
                       crl_list->tbs.p,
                       crl_list->tbs.len,
                       hash) != 0) {
            /* Note: this can't happen except after an internal error */
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        if (x509_profile_check_key(profile, &ca->pk) != 0) {
            flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
        }

        if (mbedtls_pk_verify_ext(crl_list->sig_pk, crl_list->sig_opts, &ca->pk,
                                  crl_list->sig_md, hash, hash_length,
                                  crl_list->sig.p, crl_list->sig.len) != 0) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check for validity of CRL (Do not drop out)
         */
        if (mbedtls_x509_time_is_past(&crl_list->next_update)) {
            flags |= MBEDTLS_X509_BADCRL_EXPIRED;
        }

        if (mbedtls_x509_time_is_future(&crl_list->this_update)) {
            flags |= MBEDTLS_X509_BADCRL_FUTURE;
        }

        /*
         * Check if certificate is revoked
         */
        if (mbedtls_x509_crt_is_revoked(crt, crl_list)) {
            flags |= MBEDTLS_X509_BADCERT_REVOKED;
            break;
        }

        crl_list = crl_list->next;
    }

    return flags;
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */

static int x509_crt_check_signature(const mbedtls_x509_crt *child,
                                    mbedtls_x509_crt *parent,
                                    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    size_t hash_len;
    unsigned char hash[MBEDTLS_HASH_MAX_SIZE];
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type(child->sig_md);
    hash_len = mbedtls_md_get_size(md_info);

    /* Note: hash errors can happen only after an internal error */
    if (mbedtls_md(md_info, child->tbs.p, child->tbs.len, hash) != 0) {
        my_printf("x509_crt_check_signature - exit 1\n");
        return -1;
    }

    /* Skip expensive computation on obvious mismatch */
    if (!mbedtls_pk_can_do(&parent->pk, child->sig_pk)) {
        my_printf("x509_crt_check_signature - exit 2\n");
        return -1;
    }

    (void) rs_ctx;

    return mbedtls_pk_verify_ext(child->sig_pk, child->sig_opts, &parent->pk,
                                 child->sig_md, hash, hash_len,
                                 child->sig.p, child->sig.len);
}

static int x509_crt_check_parent(const mbedtls_x509_crt *child,
                                 const mbedtls_x509_crt *parent,
                                 int top)
{
    int need_ca_bit;

    /* Parent must be the issuer */
    if (x509_name_cmp(&child->issuer, &parent->subject) != 0) {
        my_printf("x509_crt_check_parent - exit 1\n");
        return -1;
    }

    /* Parent must have the basicConstraints CA bit set as a general rule */
    need_ca_bit = 1;

    my_printf("x509_crt_check_parent - top=%d, version=%d\n", top, parent->version);

    /* Exception: v1/v2 certificates that are locally trusted. */
    if (top && parent->version < 3) {
        need_ca_bit = 0;
    }

    my_printf("x509_crt_check_parent - need_ca_bit=%d, ca_istrue=%d\n", need_ca_bit, parent->ca_istrue);

    if (need_ca_bit && !parent->ca_istrue) {
        my_printf("x509_crt_check_parent - exit 2\n");
        return -1;
    }

    if (need_ca_bit &&
        mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN) != 0) {
        my_printf("x509_crt_check_parent - exit 3\n");
        return -1;
    }

    my_printf("x509_crt_check_parent - return\n");
    return 0;
}

static int x509_crt_find_parent_in(
    mbedtls_x509_crt *child,
    mbedtls_x509_crt *candidates,
    mbedtls_x509_crt **r_parent,
    int *r_signature_is_good,
    int top,
    unsigned path_cnt,
    unsigned self_cnt,
    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *parent, *fallback_parent;
    int signature_is_good = 0, fallback_signature_is_good;

    int i = 0;

    fallback_parent = NULL;
    fallback_signature_is_good = 0;

    for (parent = candidates; parent != NULL; parent = parent->next) {

        my_printf("x509_crt_find_parent_in - iteration %d\n", i);
        i++;

        /* basic parenting skills (name, CA bit, key usage) */
        if (x509_crt_check_parent(child, parent, top) != 0) {
            my_printf("x509_crt_find_parent_in - continue 1\n");
            continue;
        }

        /* +1 because stored max_pathlen is 1 higher that the actual value */
        if (parent->max_pathlen > 0 &&
            (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt) {
            my_printf("x509_crt_find_parent_in - continue 2\n");
            continue;
        }

        /* Signature */
        ret = x509_crt_check_signature(child, parent, rs_ctx);

        (void) ret;

        signature_is_good = ret == 0;
        if (top && !signature_is_good) {
            my_printf("x509_crt_find_parent_in - continue 3\n");
            continue;
        }

        /* optional time check */
        if (mbedtls_x509_time_is_past(&parent->valid_to) ||
            mbedtls_x509_time_is_future(&parent->valid_from)) {
            if (fallback_parent == NULL) {
                fallback_parent = parent;
                fallback_signature_is_good = signature_is_good;
            }

            my_printf("x509_crt_find_parent_in - continue 4\n");
            continue;
        }

        *r_parent = parent;
        *r_signature_is_good = signature_is_good;

        my_printf("x509_crt_find_parent_in - break\n");
        break;
    }

    if (parent == NULL) {
        *r_parent = fallback_parent;
        *r_signature_is_good = fallback_signature_is_good;
        my_printf("x509_crt_find_parent_in - parent is NULL\n");
    }

    my_printf("x509_crt_find_parent_in - return\n");    

    return 0;
}

static int x509_crt_find_parent(
    mbedtls_x509_crt *child,
    mbedtls_x509_crt *trust_ca,
    mbedtls_x509_crt **parent,
    int *parent_is_trusted,
    int *signature_is_good,
    unsigned path_cnt,
    unsigned self_cnt,
    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *search_list;

    *parent_is_trusted = 1;

    int i = 0;

    while (1) {
        search_list = *parent_is_trusted ? trust_ca : child->next;

        my_printf("x509_crt_find_parent - iteration %d\n", i);
        i++;

        ret = x509_crt_find_parent_in(child, search_list,
                                      parent, signature_is_good,
                                      *parent_is_trusted,
                                      path_cnt, self_cnt, rs_ctx);

        (void) ret;

        /* stop here if found or already in second iteration */
        if (*parent != NULL || *parent_is_trusted == 0) {
            break;
        }

        /* prepare second iteration */
        *parent_is_trusted = 0;
    }

    /* extra precaution against mistakes in the caller */
    if (*parent == NULL) {
        *parent_is_trusted = 0;
        *signature_is_good = 0;
    }

    return 0;
}

static int x509_crt_check_ee_locally_trusted(
    mbedtls_x509_crt *crt,
    mbedtls_x509_crt *trust_ca)
{
    mbedtls_x509_crt *cur;

    /* must be self-issued */
    if (x509_name_cmp(&crt->issuer, &crt->subject) != 0) {
        return -1;
    }

    /* look for an exact match with trusted cert */
    for (cur = trust_ca; cur != NULL; cur = cur->next) {
        if (crt->raw.len == cur->raw.len &&
            my_memcmp(crt->raw.p, cur->raw.p, crt->raw.len) == 0) {
            return 0;
        }
    }

    /* too bad */
    return -1;
}

static int x509_crt_verify_chain(
    mbedtls_x509_crt *crt,
    mbedtls_x509_crt *trust_ca,
    mbedtls_x509_crl *ca_crl,
    mbedtls_x509_crt_ca_cb_t f_ca_cb,
    void *p_ca_cb,
    const mbedtls_x509_crt_profile *profile,
    mbedtls_x509_crt_verify_chain *ver_chain,
    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    /* Don't initialize any of those variables here, so that the compiler can
     * catch potential issues with jumping ahead when restarting */
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t *flags;
    mbedtls_x509_crt_verify_chain_item *cur;
    mbedtls_x509_crt *child;
    mbedtls_x509_crt *parent;
    int parent_is_trusted;
    int child_is_trusted;
    int signature_is_good;
    unsigned self_cnt;
    mbedtls_x509_crt *cur_trust_ca = NULL;

    child = crt;
    self_cnt = 0;
    parent_is_trusted = 0;
    child_is_trusted = 0;

    int i = 0;

    while (1) {
        /* Add certificate to the verification chain */
        cur = &ver_chain->items[ver_chain->len];
        cur->crt = child;
        cur->flags = 0;
        ver_chain->len++;
        flags = &cur->flags;

        my_printf("x509_crt_verify_chain - iteration %d\n", i);
        i++;

        /* Check time-validity (all certificates) */
        if (mbedtls_x509_time_is_past(&child->valid_to)) {
            *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
        }

        if (mbedtls_x509_time_is_future(&child->valid_from)) {
            *flags |= MBEDTLS_X509_BADCERT_FUTURE;
        }

        if(checkTCIValue(&child->subject, &child->hash)){
            my_printf("x509_crt_verify_chain - failed TCI\n");
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
        }

        /* Stop here for trusted roots (but not for trusted EE certs) */
        if (child_is_trusted) {
            my_printf("x509_crt_verify_chain - exit 1\n");
            return 0;
        }

        /* Check signature algorithm: MD & PK algs */
        if (x509_profile_check_md_alg(profile, child->sig_md) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_MD;
        }

        if (x509_profile_check_pk_alg(profile, child->sig_pk) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_PK;
        }

        /* Special case: EE certs that are locally trusted */
        if (ver_chain->len == 1 &&
            x509_crt_check_ee_locally_trusted(child, trust_ca) == 0) {
            my_printf("x509_crt_verify_chain - exit 2\n");
            return 0;
        }

        /* Obtain list of potential trusted signers from CA callback,
         * or use statically provided list. */
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
        if (f_ca_cb != NULL) {
            mbedtls_x509_crt_free(ver_chain->trust_ca_cb_result);
            mbedtls_free(ver_chain->trust_ca_cb_result);
            ver_chain->trust_ca_cb_result = NULL;

            ret = f_ca_cb(p_ca_cb, child, &ver_chain->trust_ca_cb_result);
            if (ret != 0) {
                return MBEDTLS_ERR_X509_FATAL_ERROR;
            }

            cur_trust_ca = ver_chain->trust_ca_cb_result;
        } else
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
        {
            ((void) f_ca_cb);
            ((void) p_ca_cb);
            cur_trust_ca = trust_ca;
        }

        /* Look for a parent in trusted CAs or up the chain */
        ret = x509_crt_find_parent(child, cur_trust_ca, &parent,
                                   &parent_is_trusted, &signature_is_good,
                                   ver_chain->len - 1, self_cnt, rs_ctx);

        (void) ret;

        /* No parent? We're done here */
        if (parent == NULL) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            my_printf("x509_crt_verify_chain - exit 3\n");
            return 0;
        }

        /* Count intermediate self-issued (not necessarily self-signed) certs.
         * These can occur with some strategies for key rollover, see [SIRO],
         * and should be excluded from max_pathlen checks. */
        if (ver_chain->len != 1 &&
            x509_name_cmp(&child->issuer, &child->subject) == 0) {
            self_cnt++;
        }

        /* path_cnt is 0 for the first intermediate CA,
         * and if parent is trusted it's not an intermediate CA */
        if (!parent_is_trusted &&
            ver_chain->len > MBEDTLS_X509_MAX_INTERMEDIATE_CA) {
            /* return immediately to avoid overflow the chain array */
            my_printf("x509_crt_verify_chain - exit 4\n");
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }

        /* signature was checked while searching parent */
        if (!signature_is_good) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        }

        /* check size of signing key */
        if (x509_profile_check_key(profile, &parent->pk) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
        }

#if defined(MBEDTLS_X509_CRL_PARSE_C)
        /* Check trusted CA's CRL for the given crt */
        *flags |= x509_crt_verifycrl(child, parent, ca_crl, profile);
#else
        (void) ca_crl;
#endif

        /* prepare for next iteration */
        child = parent;
        parent = NULL;
        child_is_trusted = parent_is_trusted;
        signature_is_good = 0;
    }
}

static int x509_crt_check_cn(const mbedtls_x509_buf *name,
                             const char *cn, size_t cn_len)
{
    /* try exact match */
    if (name->len == cn_len &&
        x509_memcasecmp(cn, name->p, cn_len) == 0) {
        return 0;
    }

    /* try wildcard match */
    if (x509_check_wildcard(cn, name) == 0) {
        return 0;
    }

    return -1;
}

static int x509_crt_check_san(const mbedtls_x509_buf *name,
                              const char *cn, size_t cn_len)
{
    const unsigned char san_type = (unsigned char) name->tag &
                                   MBEDTLS_ASN1_TAG_VALUE_MASK;

    /* dNSName */
    if (san_type == MBEDTLS_X509_SAN_DNS_NAME) {
        return x509_crt_check_cn(name, cn, cn_len);
    }

    /* (We may handle other types here later.) */

    /* Unrecognized type */
    return -1;
}

static void x509_crt_verify_name(const mbedtls_x509_crt *crt,
                                 const char *cn,
                                 uint32_t *flags)
{
    const mbedtls_x509_name *name;
    const mbedtls_x509_sequence *cur;
    size_t cn_len = my_strlen(cn);

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        for (cur = &crt->subject_alt_names; cur != NULL; cur = cur->next) {
            if (x509_crt_check_san(&cur->buf, cn, cn_len) == 0) {
                break;
            }
        }

        if (cur == NULL) {
            *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
    } else {
        for (name = &crt->subject; name != NULL; name = name->next) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                x509_crt_check_cn(&name->val, cn, cn_len) == 0) {
                break;
            }
        }

        if (name == NULL) {
            *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
    }
}

static int x509_crt_merge_flags_with_cb(
    uint32_t *flags,
    const mbedtls_x509_crt_verify_chain *ver_chain,
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
    void *p_vrfy)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned i;
    uint32_t cur_flags;
    const mbedtls_x509_crt_verify_chain_item *cur;

    for (i = ver_chain->len; i != 0; --i) {
        cur = &ver_chain->items[i-1];
        cur_flags = cur->flags;
        my_printf("x509_crt_merge_flags_with_cb - %d - cur_flags=%u\n", i, cur_flags);

        if (NULL != f_vrfy) {
            if ((ret = f_vrfy(p_vrfy, cur->crt, (int) i-1, &cur_flags)) != 0) {
                return ret;
            }
        }

        *flags |= cur_flags;
    }

    return 0;
}

static int x509_crt_verify_restartable_ca_cb(mbedtls_x509_crt *crt,
                                             mbedtls_x509_crt *trust_ca,
                                             mbedtls_x509_crl *ca_crl,
                                             mbedtls_x509_crt_ca_cb_t f_ca_cb,
                                             void *p_ca_cb,
                                             const mbedtls_x509_crt_profile *profile,
                                             const char *cn, uint32_t *flags,
                                             int (*f_vrfy)(void *,
                                                           mbedtls_x509_crt *,
                                                           int,
                                                           uint32_t *),
                                             void *p_vrfy,
                                             mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_pk_type_t pk_type;
    mbedtls_x509_crt_verify_chain ver_chain;
    uint32_t ee_flags;

    *flags = 0;
    ee_flags = 0;
    x509_crt_verify_chain_reset(&ver_chain);

    if (profile == NULL) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        my_printf("x509_crt_verify_restartable_ca_cb - exit 1\n");
        goto exit;
    }

    /* check name if requested */
    if (cn != NULL) {
        x509_crt_verify_name(crt, cn, &ee_flags);
    }

    my_printf("x509_crt_verify_restartable_ca_cb - 1-ee_flags=%u\n", ee_flags);

    /* Check the type and size of the key */
    pk_type = mbedtls_pk_get_type(&crt->pk);

    if (x509_profile_check_pk_alg(profile, pk_type) != 0) {
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_PK;
    }

    my_printf("x509_crt_verify_restartable_ca_cb - 2-ee_flags=%u\n", ee_flags);

    if (x509_profile_check_key(profile, &crt->pk) != 0) {
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
    }

    my_printf("x509_crt_verify_restartable_ca_cb - 3-ee_flags=%u\n", ee_flags);

    /* Check the chain */
    ret = x509_crt_verify_chain(crt, trust_ca, ca_crl,
                                f_ca_cb, p_ca_cb, profile,
                                &ver_chain, rs_ctx);

    if (ret != 0) {
        my_printf("x509_crt_verify_restartable_ca_cb - exit 2\n");
        goto exit;
    }

    /* Merge end-entity flags */
    ver_chain.items[0].flags |= ee_flags;

    my_printf("x509_crt_verify_restartable_ca_cb - 4-item_flags=%u\n", ver_chain.items[0].flags);

    /* Build final flags, calling callback on the way if any */
    ret = x509_crt_merge_flags_with_cb(flags, &ver_chain, f_vrfy, p_vrfy);

exit:

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    mbedtls_x509_crt_free(ver_chain.trust_ca_cb_result);
    mbedtls_free(ver_chain.trust_ca_cb_result);
    ver_chain.trust_ca_cb_result = NULL;
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

    /* prevent misuse of the vrfy callback - VERIFY_FAILED would be ignored by
     * the SSL module for authmode optional, but non-zero return from the
     * callback means a fatal error so it shouldn't be ignored */
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        my_printf("x509_crt_verify_restartable_ca_cb - exit 3\n");
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
    }

    if (ret != 0) {
        *flags = (uint32_t) -1;
        my_printf("x509_crt_verify_restartable_ca_cb - exit 4\n");
        return ret;
    }

    if (*flags != 0) {
        my_printf("x509_crt_verify_restartable_ca_cb - exit 5\n");
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }

    return 0;
}

int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt,
                            mbedtls_x509_crt *trust_ca,
                            mbedtls_x509_crl *ca_crl,
                            const char *cn, uint32_t *flags,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy)
{
    return x509_crt_verify_restartable_ca_cb(crt, trust_ca, ca_crl,
                                             NULL, NULL,
                                             &mbedtls_x509_crt_profile_keystone,
                                             cn, flags,
                                             f_vrfy, p_vrfy, NULL);
}

void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
    my_memset(crt, 0, sizeof(mbedtls_x509_crt));
}

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
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("mbedtls_x509_crt_free - free: %lu\n", cert_cur->raw.len);
            #endif
        }

        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        mbedtls_platform_zeroize(cert_prv, sizeof(mbedtls_x509_crt));
        if (cert_prv != crt) {
            mbedtls_free(cert_prv);
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("mbedtls_x509_crt_free - free: %lu\n", sizeof(mbedtls_x509_crt));
            #endif
        }
    }
}

// x509write_crt.c
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    my_memset(ctx, 0, sizeof(mbedtls_x509write_cert));

    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
}

void mbedtls_x509write_crt_free(mbedtls_x509write_cert *ctx)
{
    mbedtls_asn1_free_named_data_list(&ctx->subject);
    mbedtls_asn1_free_named_data_list(&ctx->issuer);
    mbedtls_asn1_free_named_data_list(&ctx->extensions);

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_x509write_cert));
}

void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx,
                                      mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

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

int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len)
{
    if (serial_len > MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ctx->serial_len = serial_len;
    my_memcpy(ctx->serial, serial, serial_len);

    return 0;
}

int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx,
                                       const char *not_before,
                                       const char *not_after)
{
    if (my_strlen(not_before) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        my_strlen(not_after)  != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    my_strncpy(ctx->not_before, not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    my_strncpy(ctx->not_after, not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return mbedtls_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int mbedtls_x509write_crt_set_basic_constraints(mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[9];
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    my_memset(buf, 0, sizeof(buf));

    if (is_ca && max_pathlen > 127) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if (is_ca) {
        if (max_pathlen >= 0) {
            MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf,
                                                             max_pathlen));
        }
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(&c, buf, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return
        mbedtls_x509write_crt_set_extension(ctx, MBEDTLS_OID_BASIC_CONSTRAINTS,
                                            MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS),
                                            is_ca, buf + sizeof(buf) - len, len);
}

static int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    /*
     * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if (t[0] < '2' || (t[0] == '2' && t[1] == '0' && t[2] < '5')) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t + 2,
                                                                size - 2));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_UTC_TIME));
    } else {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t,
                                                                size));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_GENERALIZED_TIME));
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("x509_write_time - len = %d\n", len);
    #endif
    return (int) len;
}

int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng) // new_impl
{
    //, unsigned char* test, int *l_topass){
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
    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("sig_oid", (unsigned char*) sig_oid, sig_oid_len);
    #endif
    // sig_oid = "{0x2B, 0x65, 0x70}";
    // sig_oid_len = 3;

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if (ctx->version == MBEDTLS_X509_CRT_VERSION_3) {
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

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - extensions: %d\n", len);
    #endif
    /*
     *  SubjectPublicKeyInfo
     */
    MBEDTLS_ASN1_CHK_ADD(pub_len,
                         mbedtls_pk_write_pubkey_der(ctx->subject_key,
                                                     buf, c - buf));
    c -= pub_len;
    len += pub_len;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - subPKInfo: %d\n", len);
    #endif
    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names(&c, buf,
                                                  ctx->subject));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - subject: %d\n", len);
    #endif
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

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - validity: %d\n", len);
    #endif
    /*
     *  Issuer  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf,
                                                       ctx->issuer));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - issuer: %d\n", len);
    #endif
    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(&c, buf,
                                                                 sig_oid, sig_oid_len, 0));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - aId: %d\n", len);
    #endif
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
    if (*c & 0x80) {
        if (c - buf < 1) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        *(--c) = 0x0;
        len++;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len + 1));
    } else {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_INTEGER));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - serial: %d\n", len);
    #endif
    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */
    if (ctx->version != MBEDTLS_X509_CRT_VERSION_1) {
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
                         mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - version: %d\n", len);
    #endif
    /* *
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
                               f_rng, p_rng)) != 0) {
        return ret;
    }
    */

    mbedtls_ed25519_context *ed25519 = mbedtls_pk_ed25519(*(ctx->issuer_key));
    if(ed25519->no_priv_key == 0) {
        ed25519_sign(sig, hash, 64, ed25519->pub_key, ed25519->priv_key);
        sig_len = 64;
    } else {
        crypto_interface(2, (void*) hash, MBEDTLS_HASH_MAX_SIZE, sig, &sig_len, ed25519->pub_key);
    }
    
    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    my_memmove(buf, c, len);
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size;
    if (sig_oid != NULL) {
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

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("len - signature: %d\n", len);
    #endif
    return (int) len;
}

