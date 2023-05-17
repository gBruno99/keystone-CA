#include "custom_functions.h"
#include "sha3.h"
#include "ed25519/ed25519.h"

// x509_crt.c
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

        // my_memcpy(crt->hash.p_arr,*p, 64);

        crt->hash.p = *p;
        crt->hash.len = 64;
        *p += 64;

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

        my_memcpy(crt->raw.p, buf, crt->raw.len);
        crt->own_buffer = 1;

        p += crt->raw.len - len;
        end = crt_end = p + len;
    } else {
        crt->raw.p = (unsigned char *) buf;
        crt->own_buffer = 0;
    }

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

    /*
     * SubjectPublicKeyInfo
     */
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0) {
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
            // mbedtls_platform_zeroize(cert_cur->raw.p, cert_cur->raw.len);
            my_memset(cert_cur->raw.p, 0x00, cert_cur->raw.len);
            mbedtls_free(cert_cur->raw.p);
        }

        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        // mbedtls_platform_zeroize(cert_prv, sizeof(mbedtls_x509_crt));
        my_memset(cert_prv, 0x00, sizeof(mbedtls_x509_crt));
        if (cert_prv != crt) {
            mbedtls_free(cert_prv);
        }
    }
}

// x509write_crt.c
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    my_memset(ctx, 0, sizeof(mbedtls_x509write_cert));

    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
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
                                                                 sig_oid, my_strlen(sig_oid), 0));

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

    ed25519_sign(sig, hash, 64, mbedtls_pk_ed25519(*(ctx->issuer_key))->pub_key, mbedtls_pk_ed25519(*(ctx->issuer_key))->priv_key);
    sig_len = 64;

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

    return (int) len;
}

