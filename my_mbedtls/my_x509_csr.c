#include "custom_functions.h"

// custom new_impl
static int mbedtls_x509_get_nonce(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *nonce) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_get_nonce\n");
    #endif

    if ((ret = mbedtls_asn1_get_bitstring(p, end, &bs)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    /* A bitstring with no flags set is still technically valid, as it will mean
       that the certificate has no designated purpose at the time of creation. */
    if (bs.len == 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    /* Get actual bitstring */
    nonce->len = bs.len;
    nonce->p = bs.p;

    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("mbedtls_x509_get_nonce", nonce->p, nonce->len);
    #endif

    return 0;
}

static int mbedtls_x509_get_attestation_proof(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *attestation_proof) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_bitstring bs = { 0, 0, NULL };

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_get_attestation_proof\n");
    #endif

    if ((ret = mbedtls_asn1_get_bitstring(p, end, &bs)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    /* A bitstring with no flags set is still technically valid, as it will mean
       that the certificate has no designated purpose at the time of creation. */
    if (bs.len == 0) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    /* Get actual bitstring */
    attestation_proof->len = bs.len;
    attestation_proof->p = bs.p;

    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("mbedtls_x509_get_attestation_proof", attestation_proof->p, attestation_proof->len);
    #endif

    return 0;
}

static int get_certs(unsigned char **p, const unsigned char *end, mbedtls_x509_crt *cert_chain) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p + len > end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if((ret = mbedtls_x509_crt_parse_der(cert_chain, *p, len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    *p += len;

    return 0;
}

static int mbedtls_x509_get_dice_certs(unsigned char **p, const unsigned char *end, mbedtls_x509_crt *cert_chain) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data;

    mbedtls_x509_crt_init(cert_chain);
    
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    end_ext_data = *p + len;

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    return 0;
}

// x509_csr.c
static int x509_csr_get_version(unsigned char **p,
                                const unsigned char *end,
                                int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_int(p, end, ver)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            *ver = 0;
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION, ret);
    }

    return 0;
}

static int x509_csr_parse_extensions(mbedtls_x509_csr *csr,
                                     unsigned char **p, const unsigned char *end)
{
    int ret;
    size_t len;
    unsigned char *end_ext_data;
    while (*p < end) {
        
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("x509_csr_parse_extensions - ...\n");
        #endif

        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int ext_type = 0;

        /* Read sequence tag */
        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("x509_csr_parse_extensions - error 1\n");
            #endif
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("x509_csr_parse_extensions - error 2\n");
            #endif
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("x509_csr_parse_extensions - error 3\n");
            #endif
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        if (*p + len != end_ext_data) {
            #if MBEDTLS_DEBUG_PRINTS
            my_printf("x509_csr_parse_extensions - error 4\n");
            #endif
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        /*
         * Detect supported extensions and skip unsupported extensions
         */
        ret = mbedtls_oid_get_x509_ext_type(&extn_oid, &ext_type);

        if (ret == 0) {
            /* Forbid repeated extensions */
            if ((csr->ext_types & ext_type) != 0) {
                #if MBEDTLS_DEBUG_PRINTS
                my_printf("x509_csr_parse_extensions - error 5\n");
                #endif
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                         MBEDTLS_ERR_ASN1_INVALID_DATA);
            }

            csr->ext_types |= ext_type;

            switch (ext_type) {
                case MBEDTLS_X509_EXT_KEY_USAGE:
                    /* Parse key usage */
                    if ((ret = mbedtls_x509_get_key_usage(p, end_ext_data,
                                                          &csr->key_usage)) != 0) {
                        return ret;
                    }
                    break;

                case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
                    /* Parse subject alt name */
                    if ((ret = mbedtls_x509_get_subject_alt_name(p, end_ext_data,
                                                                 &csr->subject_alt_names)) != 0) {
                        return ret;
                    }
                    break;

                case MBEDTLS_X509_EXT_NS_CERT_TYPE:
                    /* Parse netscape certificate type */
                    if ((ret = mbedtls_x509_get_ns_cert_type(p, end_ext_data,
                                                             &csr->ns_cert_type)) != 0) {
                        return ret;
                    }
                    break;
                case MBEDTLS_X509_EXT_NONCE: // new_impl
                    /* Parse nonce */
                    if((ret = mbedtls_x509_get_nonce(p, end_ext_data, 
                                                    &csr->nonce)) != 0){
                        return ret;
                    }
                    break;
                case MBEDTLS_X509_EXT_DICE_CERTS: // new_impl
                    /* Parse dice certs */
                    if((ret = mbedtls_x509_get_dice_certs(p, end_ext_data, 
                                                    &csr->cert_chain)) != 0){
                        return ret;
                    }
                    break;
                case MBEDTLS_X509_EXT_ATTESTATION_PROOF: // new_impl
                    /* Parse attestation proof */
                    if((ret = mbedtls_x509_get_attestation_proof(p, end_ext_data, 
                                                                &csr->attestation_proof)) != 0){
                        return ret;
                    }
                    break;
                default:
                    break;
            }
        }
        *p = end_ext_data;
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

static int x509_csr_parse_attributes(mbedtls_x509_csr *csr,
                                     const unsigned char *start, const unsigned char *end)
{
    int ret;
    size_t len;
    unsigned char *end_attr_data;
    unsigned char **p = (unsigned char **) &start;

    while (*p < end) {
        mbedtls_x509_buf attr_oid = { 0, 0, NULL };

        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        end_attr_data = *p + len;

        /* Get attribute ID */
        if ((ret = mbedtls_asn1_get_tag(p, end_attr_data, &attr_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        attr_oid.tag = MBEDTLS_ASN1_OID;
        attr_oid.p = *p;
        *p += attr_oid.len;

        /* Check that this is an extension-request attribute */
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS9_CSR_EXT_REQ, &attr_oid) == 0) {
            if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
                0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            if ((ret = x509_csr_parse_extensions(csr, p, *p + len)) != 0) {
                return ret;
            }

            if (*p != end_attr_data) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                         MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
            }
        }

        *p = end_attr_data;
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int mbedtls_x509_csr_parse_der(mbedtls_x509_csr *csr,
                               const unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end;
    mbedtls_x509_buf sig_params;

    my_memset(&sig_params, 0, sizeof(mbedtls_x509_buf));

    /*
     * Check for valid input
     */
    if (csr == NULL || buf == NULL || buflen == 0) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    mbedtls_x509_csr_init(csr);

    /*
     * first copy the raw DER data
     */
    p = mbedtls_calloc(1, len = buflen);

    if (p == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - calloc: %lu\n", len);
    #endif

    my_memcpy(p, buf, buflen);

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (len != (size_t) (end - p)) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - sequence\n");
    #endif

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - info\n");
    #endif

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if ((ret = x509_csr_get_version(&p, end, &csr->version)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    if (csr->version != 0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }

    csr->version++;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - version\n");
    #endif

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    if ((ret = mbedtls_x509_get_name(&p, p + len, &csr->subject)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - subject\n");
    #endif

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &csr->pk)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - pk \n");
    #endif

    /*
     *  attributes    [0] Attributes
     *
     *  The list of possible attributes is open-ended, though RFC 2985
     *  (PKCS#9) defines a few in section 5.4. We currently don't support any,
     *  so we just ignore them. This is a safe thing to do as the worst thing
     *  that could happen is that we issue a certificate that does not match
     *  the requester's expectations - this cannot cause a violation of our
     *  signature policies.
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) !=
        0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    if ((ret = x509_csr_parse_attributes(csr, p, p + len)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - attributes\n");
    #endif

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if ((ret = mbedtls_x509_get_alg(&p, end, &csr->sig_oid, &sig_params)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    if ((ret = mbedtls_x509_get_sig_alg(&csr->sig_oid, &sig_params,
                                        &csr->sig_md, &csr->sig_pk,
                                        &csr->sig_opts)) != 0) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG;
    }

    if ((ret = mbedtls_x509_get_sig(&p, end, &csr->sig)) != 0) {
        mbedtls_x509_csr_free(csr);
        return ret;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - signature\n");
    #endif

    if (p != end) {
        mbedtls_x509_csr_free(csr);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509_csr_parse_der - success\n");
    #endif

    return 0;
}

void mbedtls_x509_csr_init(mbedtls_x509_csr *csr)
{
    my_memset(csr, 0, sizeof(mbedtls_x509_csr));
}

void mbedtls_x509_csr_free(mbedtls_x509_csr *csr)
{
    if (csr == NULL) {
        return;
    }

    mbedtls_pk_free(&csr->pk);

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free(csr->sig_opts);
#endif

    mbedtls_x509_crt_free(&(csr->cert_chain));

    mbedtls_asn1_free_named_data_list_shallow(csr->subject.next);
    mbedtls_asn1_sequence_free(csr->subject_alt_names.next);

    if (csr->raw.p != NULL) {
        mbedtls_platform_zeroize(csr->raw.p, csr->raw.len);
        mbedtls_free(csr->raw.p);
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("mbedtls_x509_csr_free - free: %lu\n", csr->raw.len);
        #endif
    }

    mbedtls_platform_zeroize(csr, sizeof(mbedtls_x509_csr));
}

// x509write_csr.c
void mbedtls_x509write_csr_init(mbedtls_x509write_csr *ctx)
{
    my_memset(ctx, 0, sizeof(mbedtls_x509write_csr));
}

void mbedtls_x509write_csr_free(mbedtls_x509write_csr *ctx)
{
    mbedtls_asn1_free_named_data_list(&ctx->subject);
    mbedtls_asn1_free_named_data_list(&ctx->extensions);

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_x509write_csr));
}

void mbedtls_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

void mbedtls_x509write_csr_set_key(mbedtls_x509write_csr *ctx, mbedtls_pk_context *key)
{
    ctx->key = key;
}

int mbedtls_x509write_csr_set_subject_name(mbedtls_x509write_csr *ctx,
                                           const char *subject_name)
{
    return mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

int mbedtls_x509write_csr_set_extension(mbedtls_x509write_csr *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return mbedtls_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int mbedtls_x509write_csr_set_subject_alternative_name(mbedtls_x509write_csr *ctx,
                                                       const mbedtls_x509_san_list *san_list)
{
    int ret = 0;
    const mbedtls_x509_san_list *cur;
    unsigned char *buf;
    unsigned char *p;
    size_t len;
    size_t buflen = 0;

    /* Determine the maximum size of the SubjectAltName list */
    for (cur = san_list; cur != NULL; cur = cur->next) {
        /* Calculate size of the required buffer */
        switch (cur->node.type) {
            case MBEDTLS_X509_SAN_DNS_NAME:
            case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case MBEDTLS_X509_SAN_IP_ADDRESS:
                /* length of value for each name entry,
                 * maximum 4 bytes for the length field,
                 * 1 byte for the tag/type.
                 */
                buflen += cur->node.san.unstructured_name.len + 4 + 1;
                break;

            default:
                /* Not supported - skip. */
                break;
        }
    }

    /* Add the extra length field and tag */
    buflen += 4 + 1;

    /* Allocate buffer */
    buf = mbedtls_calloc(1, buflen);
    if (buf == NULL) {
        return MBEDTLS_ERR_ASN1_ALLOC_FAILED;
    }
    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509write_csr_set_subject_alternative_name - calloc: %lu\n", buflen);
    #endif

    mbedtls_platform_zeroize(buf, buflen);
    p = buf + buflen;

    /* Write ASN.1-based structure */
    cur = san_list;
    len = 0;
    while (cur != NULL) {
        switch (cur->node.type) {
            case MBEDTLS_X509_SAN_DNS_NAME:
            case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case MBEDTLS_X509_SAN_IP_ADDRESS:
            {
                const unsigned char *unstructured_name =
                    (const unsigned char *) cur->node.san.unstructured_name.p;
                size_t unstructured_name_len = cur->node.san.unstructured_name.len;

                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len,
                                             mbedtls_asn1_write_raw_buffer(
                                                 &p, buf,
                                                 unstructured_name, unstructured_name_len));
                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_len(
                                                 &p, buf, unstructured_name_len));
                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len,
                                             mbedtls_asn1_write_tag(
                                                 &p, buf,
                                                 MBEDTLS_ASN1_CONTEXT_SPECIFIC | cur->node.type));
            }
            break;
            default:
                /* Skip unsupported names. */
                break;
        }
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_CLEANUP_ADD(len,
                                 mbedtls_asn1_write_tag(&p, buf,
                                                        MBEDTLS_ASN1_CONSTRUCTED |
                                                        MBEDTLS_ASN1_SEQUENCE));

    ret = mbedtls_x509write_csr_set_extension(
        ctx,
        MBEDTLS_OID_SUBJECT_ALT_NAME,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
        0,
        buf + buflen - len,
        len);

    /* If we exceeded the allocated buffer it means that maximum size of the SubjectAltName list
     * was incorrectly calculated and memory is corrupted. */
    if (p < buf) {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

cleanup:
    mbedtls_free(buf);
    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509write_csr_set_subject_alternative_name - free: %lu\n", buflen);
    #endif
    return ret;
}

int mbedtls_x509write_csr_set_key_usage(mbedtls_x509write_csr *ctx, unsigned char key_usage)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = mbedtls_asn1_write_named_bitstring(&c, buf, &key_usage, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_KEY_USAGE,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int mbedtls_x509write_csr_set_ns_cert_type(mbedtls_x509write_csr *ctx,
                                           unsigned char ns_cert_type)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = mbedtls_asn1_write_named_bitstring(&c, buf, &ns_cert_type, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_NS_CERT_TYPE,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_NS_CERT_TYPE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int x509write_csr_der_internal(mbedtls_x509write_csr *ctx,
                                      unsigned char *buf,
                                      size_t size,
                                      unsigned char *sig, size_t sig_size,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[MBEDTLS_HASH_MAX_SIZE];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    size_t hash_len;
    psa_algorithm_t hash_alg = mbedtls_hash_info_psa_from_md(ctx->md_alg);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /* Write the CSR backwards starting from the end of buf */
    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_extensions(&c, buf,
                                                            ctx->extensions));

    if (len) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));

        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_oid(
                                 &c, buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
                                 MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ)));

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(
                             &c, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_pk_write_pubkey_der(ctx->key,
                                                              buf, c - buf));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf,
                                                       ctx->subject));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(
                             &c, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /*
     * Sign the written CSR data into the sig buffer
     * Note: hash errors can happen only after an internal error
     */
    ret = mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), c, len, hash);
    if (ret != 0) {
        return ret;
    }

    if ((ret = mbedtls_pk_sign(ctx->key, ctx->md_alg, hash, 0,
                               sig, sig_size, &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    if (mbedtls_pk_can_do(ctx->key, MBEDTLS_PK_ED25519)) {
        pk_alg = MBEDTLS_PK_ED25519;
    } else {
        return MBEDTLS_ERR_X509_INVALID_ALG;
    }

    if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     * Move the written CSR data to the start of buf to create space for
     * writing the signature into buf.
     */
    my_memmove(buf, c, len);

    /*
     * Write sig and its OID into buf backwards from the end of buf.
     * Note: mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
     * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len,
                         mbedtls_x509_write_sig(&c2, buf + len, sig_oid, sig_oid_len,
                                                sig, sig_len));

    /*
     * Compact the space between the CSR data and signature by moving the
     * CSR data to the start of the signature.
     */
    c2 -= len;
    my_memmove(c2, buf, len);

    /* ASN encode the total size and tag the CSR data with it. */
    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c2, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(
                             &c2, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /* Zero the unused bytes at the start of buf */
    my_memset(buf, 0, c2 - buf);

    return (int) len;
}

int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf,
                              size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret;
    unsigned char *sig;

    if ((sig = mbedtls_calloc(1, MBEDTLS_PK_SIGNATURE_MAX_SIZE)) == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509write_csr_der - calloc: %lu\n", MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    #endif

    ret = x509write_csr_der_internal(ctx, buf, size,
                                     sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE,
                                     f_rng, p_rng);

    mbedtls_free(sig);

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_x509write_csr_der - free: %lu\n", MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    #endif

    return ret;
}

// custom new_impl
static int write_certs(unsigned char **p, const unsigned char *start, unsigned char *cert, int size){
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            cert, size));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start,
                                                        size));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_OCTET_STRING));
    return (int) len;
}

int mbedtls_x509write_csr_set_dice_certs(mbedtls_x509write_csr *ctx, unsigned char *certs[], int *sizes) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    unsigned char buf[1024] = {0};

    unsigned char *c = buf + 1024;

    MBEDTLS_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[2], sizes[2]));
    MBEDTLS_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[1], sizes[1]));
    MBEDTLS_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[0], sizes[0]));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    unsigned char *parsed_certs = buf;
    int dif_certs = 1024-len;
    parsed_certs += dif_certs;

    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("asn1 cert chain", parsed_certs, len);
    #endif
    
    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_DICE_CERTS, MBEDTLS_OID_SIZE(MBEDTLS_OID_DICE_CERTS),
        0, parsed_certs, len);

    return ret;
}

int mbedtls_x509write_csr_set_nonce(mbedtls_x509write_csr *ctx, unsigned char *nonce) {
    unsigned char buf[NONCE_LEN + 3] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    
    c = buf + NONCE_LEN + 3;

    ret = mbedtls_asn1_write_named_bitstring(&c, buf, nonce, NONCE_LEN*8);
    if (ret != (NONCE_LEN + 3)) {
        return ret;
    }

    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("asn1 nonce", c, NONCE_LEN+3);
    #endif

    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_NONCE, MBEDTLS_OID_SIZE(MBEDTLS_OID_NONCE),
        0, c, (size_t) ret);

    return ret;
}

int mbedtls_x509write_csr_set_attestation_proof(mbedtls_x509write_csr *ctx, unsigned char *attest_proof) {
    unsigned char buf[ATTESTATION_PROOF_LEN + 3] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    
    c = buf + ATTESTATION_PROOF_LEN + 3;

    ret = mbedtls_asn1_write_named_bitstring(&c, buf, attest_proof, ATTESTATION_PROOF_LEN*8);
    if (ret != (ATTESTATION_PROOF_LEN + 3)) {
        return ret;
    }
    
    #if MBEDTLS_DEBUG_PRINTS
    print_hex_string("asn1 attest_proof", c, ATTESTATION_PROOF_LEN+3);
    #endif

    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_ATTESTATION_PROOF, MBEDTLS_OID_SIZE(MBEDTLS_OID_ATTESTATION_PROOF),
        0, c, (size_t) ret);

    return ret;
}
