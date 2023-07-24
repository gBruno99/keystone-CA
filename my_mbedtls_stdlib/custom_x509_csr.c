#include "custom_functions.h"

// custom new_impl
static int custom_x509_get_nonce(unsigned char **p, const unsigned char *end, custom_x509_buf *nonce) {
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_get_nonce\n");
    #endif

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_OCTET_STRING)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p + len > end || len != NONCE_LEN) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                    CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    /* Get actual bitstring */
    nonce->len = len;
    nonce->p = custom_calloc(NONCE_LEN, 1);
    custom_memcpy(nonce->p, *p, NONCE_LEN);
    *p += len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_nonce", nonce->p, nonce->len);
    #endif

    return 0;
}

static int custom_x509_get_attestation_proof(unsigned char **p, const unsigned char *end, custom_x509_buf *attestation_proof) {
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_get_attestation_proof\n");
    #endif

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_OCTET_STRING)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p + len > end || len != ATTESTATION_PROOF_LEN) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                    CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    /* Get actual bitstring */
    attestation_proof->len = len;
    attestation_proof->p = custom_calloc(ATTESTATION_PROOF_LEN, 1);
    custom_memcpy(attestation_proof->p, *p, ATTESTATION_PROOF_LEN);
    *p += len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("custom_x509_get_attestation_proof", attestation_proof->p, attestation_proof->len);
    #endif

    return 0;
}

static int get_certs(unsigned char **p, const unsigned char *end, custom_x509_crt *cert_chain) {
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_OCTET_STRING)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p + len > end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                    CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    if((ret = custom_x509_crt_parse_der(cert_chain, *p, len)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    *p += len;

    return 0;
}

static int custom_x509_get_dice_certs(unsigned char **p, const unsigned char *end, custom_x509_crt *cert_chain) {
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data;

    custom_x509_crt_init(cert_chain);
    
    if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    end_ext_data = *p + len;

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if((ret = get_certs(p, end_ext_data, cert_chain)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    return 0;
}

// x509_csr.c
static int x509_csr_get_version(unsigned char **p,
                                const unsigned char *end,
                                int *ver)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = custom_asn1_get_int(p, end, ver)) != 0) {
        if (ret == CUSTOM_ERR_ASN1_UNEXPECTED_TAG) {
            *ver = 0;
            return 0;
        }

        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_VERSION, ret);
    }

    return 0;
}

static int x509_csr_parse_extensions(custom_x509_csr *csr,
                                     unsigned char **p, const unsigned char *end)
{
    int ret;
    size_t len;
    unsigned char *end_ext_data;
    while (*p < end) {
        
        #if CUSTOM_DEBUG_PRINTS
        printf("x509_csr_parse_extensions - ...\n");
        #endif

        custom_x509_buf extn_oid = { 0, 0, NULL };
        int ext_type = 0;

        /* Read sequence tag */
        if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
            #if CUSTOM_DEBUG_PRINTS
            printf("x509_csr_parse_extensions - error 1\n");
            #endif
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = custom_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        CUSTOM_ASN1_OID)) != 0) {
            #if CUSTOM_DEBUG_PRINTS
            printf("x509_csr_parse_extensions - error 2\n");
            #endif
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        extn_oid.tag = CUSTOM_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Data should be octet string type */
        if ((ret = custom_asn1_get_tag(p, end_ext_data, &len,
                                        CUSTOM_ASN1_OCTET_STRING)) != 0) {
            #if CUSTOM_DEBUG_PRINTS
            printf("x509_csr_parse_extensions - error 3\n");
            #endif
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        if (*p + len != end_ext_data) {
            #if CUSTOM_DEBUG_PRINTS
            printf("x509_csr_parse_extensions - error 4\n");
            #endif
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                     CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
        }

        /*
         * Detect supported extensions and skip unsupported extensions
         */
        ret = custom_oid_get_x509_ext_type(&extn_oid, &ext_type);

        if (ret == 0) {
            /* Forbid repeated extensions */
            if ((csr->ext_types & ext_type) != 0) {
                #if CUSTOM_DEBUG_PRINTS
                printf("x509_csr_parse_extensions - error 5\n");
                #endif
                return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                         CUSTOM_ERR_ASN1_INVALID_DATA);
            }

            csr->ext_types |= ext_type;

            switch (ext_type) {
                case CUSTOM_X509_EXT_KEY_USAGE:
                    /* Parse key usage */
                    if ((ret = custom_x509_get_key_usage(p, end_ext_data,
                                                          &csr->key_usage)) != 0) {
                        return ret;
                    }
                    break;

                case CUSTOM_X509_EXT_SUBJECT_ALT_NAME:
                    /* Parse subject alt name */
                    if ((ret = custom_x509_get_subject_alt_name(p, end_ext_data,
                                                                 &csr->subject_alt_names)) != 0) {
                        return ret;
                    }
                    break;

                case CUSTOM_X509_EXT_NS_CERT_TYPE:
                    /* Parse netscape certificate type */
                    if ((ret = custom_x509_get_ns_cert_type(p, end_ext_data,
                                                             &csr->ns_cert_type)) != 0) {
                        return ret;
                    }
                    break;
                case CUSTOM_X509_EXT_NONCE: // new_impl
                    /* Parse nonce */
                    if((ret = custom_x509_get_nonce(p, end_ext_data, 
                                                    &csr->nonce)) != 0){
                        return ret;
                    }
                    break;
                case CUSTOM_X509_EXT_DICE_CERTS: // new_impl
                    /* Parse dice certs */
                    if((ret = custom_x509_get_dice_certs(p, end_ext_data, 
                                                    &csr->cert_chain)) != 0){
                        return ret;
                    }
                    break;
                case CUSTOM_X509_EXT_ATTESTATION_PROOF: // new_impl
                    /* Parse attestation proof */
                    if((ret = custom_x509_get_attestation_proof(p, end_ext_data, 
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
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

static int x509_csr_parse_attributes(custom_x509_csr *csr,
                                     const unsigned char *start, const unsigned char *end)
{
    int ret;
    size_t len;
    unsigned char *end_attr_data;
    unsigned char **p = (unsigned char **) &start;

    while (*p < end) {
        custom_x509_buf attr_oid = { 0, 0, NULL };

        if ((ret = custom_asn1_get_tag(p, end, &len,
                                        CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        end_attr_data = *p + len;

        /* Get attribute ID */
        if ((ret = custom_asn1_get_tag(p, end_attr_data, &attr_oid.len,
                                        CUSTOM_ASN1_OID)) != 0) {
            return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        attr_oid.tag = CUSTOM_ASN1_OID;
        attr_oid.p = *p;
        *p += attr_oid.len;

        /* Check that this is an extension-request attribute */
        if (CUSTOM_OID_CMP(CUSTOM_OID_PKCS9_CSR_EXT_REQ, &attr_oid) == 0) {
            if ((ret = custom_asn1_get_tag(p, end, &len,
                                            CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SET)) != 0) {
                return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            if ((ret = custom_asn1_get_tag(p, end, &len,
                                            CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) !=
                0) {
                return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            if ((ret = x509_csr_parse_extensions(csr, p, *p + len)) != 0) {
                return ret;
            }

            if (*p != end_attr_data) {
                return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                         CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
            }
        }

        *p = end_attr_data;
    }

    if (*p != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_EXTENSIONS,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int custom_x509_csr_parse_der(custom_x509_csr *csr,
                               const unsigned char *buf, size_t buflen)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end;
    custom_x509_buf sig_params;

    custom_memset(&sig_params, 0, sizeof(custom_x509_buf));

    /*
     * Check for valid input
     */
    if (csr == NULL || buf == NULL || buflen == 0) {
        return CUSTOM_ERR_X509_BAD_INPUT_DATA;
    }

    custom_x509_csr_init(csr);

    /*
     * first copy the raw DER data
     */
    p = custom_calloc(1, len = buflen);

    if (p == NULL) {
        return CUSTOM_ERR_X509_ALLOC_FAILED;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - calloc: %lu\n", len);
    #endif

    custom_memcpy(p, buf, buflen);

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
    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERR_X509_INVALID_FORMAT;
    }

    if (len != (size_t) (end - p)) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_FORMAT,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - sequence\n");
    #endif

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_FORMAT, ret);
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - info\n");
    #endif

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if ((ret = x509_csr_get_version(&p, end, &csr->version)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    if (csr->version != 0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERR_X509_UNKNOWN_VERSION;
    }

    csr->version++;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - version\n");
    #endif

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_FORMAT, ret);
    }

    if ((ret = custom_x509_get_name(&p, p + len, &csr->subject)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - subject\n");
    #endif

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if ((ret = custom_pk_parse_subpubkey(&p, end, &csr->pk)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - pk \n");
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
    if ((ret = custom_asn1_get_tag(&p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_CONTEXT_SPECIFIC)) !=
        0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_FORMAT, ret);
    }

    if ((ret = x509_csr_parse_attributes(csr, p, p + len)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - attributes\n");
    #endif

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if ((ret = custom_x509_get_alg(&p, end, &csr->sig_oid, &sig_params)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    if ((ret = custom_x509_get_sig_alg(&csr->sig_oid, &sig_params,
                                        &csr->sig_md, &csr->sig_pk,
                                        &csr->sig_opts)) != 0) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERR_X509_UNKNOWN_SIG_ALG;
    }

    if ((ret = custom_x509_get_sig(&p, end, &csr->sig)) != 0) {
        custom_x509_csr_free(csr);
        return ret;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - signature\n");
    #endif

    if (p != end) {
        custom_x509_csr_free(csr);
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_X509_INVALID_FORMAT,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509_csr_parse_der - success\n");
    #endif

    return 0;
}

void custom_x509_csr_init(custom_x509_csr *csr)
{
    custom_memset(csr, 0, sizeof(custom_x509_csr));
}

void custom_x509_csr_free(custom_x509_csr *csr)
{
    if (csr == NULL) {
        return;
    }

    custom_pk_free(&csr->pk);

#if defined(CUSTOM_X509_RSASSA_PSS_SUPPORT)
    custom_free(csr->sig_opts);
#endif

    custom_x509_crt_free(&(csr->cert_chain));
    custom_free(csr->attestation_proof.p);
    custom_free(csr->nonce.p);

    custom_asn1_free_named_data_list_shallow(csr->subject.next);
    custom_asn1_sequence_free(csr->subject_alt_names.next);

    if (csr->raw.p != NULL) {
        custom_platform_zeroize(csr->raw.p, csr->raw.len);
        custom_free(csr->raw.p);
        #if CUSTOM_DEBUG_PRINTS
        printf("custom_x509_csr_free - free: %lu\n", csr->raw.len);
        #endif
    }

    custom_platform_zeroize(csr, sizeof(custom_x509_csr));
}

// x509write_csr.c
void custom_x509write_csr_init(custom_x509write_csr *ctx)
{
    custom_memset(ctx, 0, sizeof(custom_x509write_csr));
}

void custom_x509write_csr_free(custom_x509write_csr *ctx)
{
    custom_asn1_free_named_data_list(&ctx->subject);
    custom_asn1_free_named_data_list(&ctx->extensions);

    custom_platform_zeroize(ctx, sizeof(custom_x509write_csr));
}

void custom_x509write_csr_set_md_alg(custom_x509write_csr *ctx, custom_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

void custom_x509write_csr_set_key(custom_x509write_csr *ctx, custom_pk_context *key)
{
    ctx->key = key;
}

int custom_x509write_csr_set_subject_name(custom_x509write_csr *ctx,
                                           const char *subject_name)
{
    return custom_x509_string_to_names(&ctx->subject, subject_name);
}

int custom_x509write_csr_set_extension(custom_x509write_csr *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return custom_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int custom_x509write_csr_set_subject_alternative_name(custom_x509write_csr *ctx,
                                                       const custom_x509_san_list *san_list)
{
    int ret = 0;
    const custom_x509_san_list *cur;
    unsigned char *buf;
    unsigned char *p;
    size_t len;
    size_t buflen = 0;

    /* Determine the maximum size of the SubjectAltName list */
    for (cur = san_list; cur != NULL; cur = cur->next) {
        /* Calculate size of the required buffer */
        switch (cur->node.type) {
            case CUSTOM_X509_SAN_DNS_NAME:
            case CUSTOM_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case CUSTOM_X509_SAN_IP_ADDRESS:
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
    buf = custom_calloc(1, buflen);
    if (buf == NULL) {
        return CUSTOM_ERR_ASN1_ALLOC_FAILED;
    }
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509write_csr_set_subject_alternative_name - calloc: %lu\n", buflen);
    #endif

    custom_platform_zeroize(buf, buflen);
    p = buf + buflen;

    /* Write ASN.1-based structure */
    cur = san_list;
    len = 0;
    while (cur != NULL) {
        switch (cur->node.type) {
            case CUSTOM_X509_SAN_DNS_NAME:
            case CUSTOM_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case CUSTOM_X509_SAN_IP_ADDRESS:
            {
                const unsigned char *unstructured_name =
                    (const unsigned char *) cur->node.san.unstructured_name.p;
                size_t unstructured_name_len = cur->node.san.unstructured_name.len;

                CUSTOM_ASN1_CHK_CLEANUP_ADD(len,
                                             custom_asn1_write_raw_buffer(
                                                 &p, buf,
                                                 unstructured_name, unstructured_name_len));
                CUSTOM_ASN1_CHK_CLEANUP_ADD(len, custom_asn1_write_len(
                                                 &p, buf, unstructured_name_len));
                CUSTOM_ASN1_CHK_CLEANUP_ADD(len,
                                             custom_asn1_write_tag(
                                                 &p, buf,
                                                 CUSTOM_ASN1_CONTEXT_SPECIFIC | cur->node.type));
            }
            break;
            default:
                /* Skip unsupported names. */
                break;
        }
        cur = cur->next;
    }

    CUSTOM_ASN1_CHK_CLEANUP_ADD(len, custom_asn1_write_len(&p, buf, len));
    CUSTOM_ASN1_CHK_CLEANUP_ADD(len,
                                 custom_asn1_write_tag(&p, buf,
                                                        CUSTOM_ASN1_CONSTRUCTED |
                                                        CUSTOM_ASN1_SEQUENCE));

    ret = custom_x509write_csr_set_extension(
        ctx,
        CUSTOM_OID_SUBJECT_ALT_NAME,
        CUSTOM_OID_SIZE(CUSTOM_OID_SUBJECT_ALT_NAME),
        0,
        buf + buflen - len,
        len);

    /* If we exceeded the allocated buffer it means that maximum size of the SubjectAltName list
     * was incorrectly calculated and memory is corrupted. */
    if (p < buf) {
        ret = CUSTOM_ERR_ASN1_LENGTH_MISMATCH;
    }

cleanup:
    custom_free(buf);
    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509write_csr_set_subject_alternative_name - free: %lu\n", buflen);
    #endif
    return ret;
}

int custom_x509write_csr_set_key_usage(custom_x509write_csr *ctx, unsigned char key_usage)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = custom_asn1_write_named_bitstring(&c, buf, &key_usage, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = custom_x509write_csr_set_extension(ctx, CUSTOM_OID_KEY_USAGE,
                                              CUSTOM_OID_SIZE(CUSTOM_OID_KEY_USAGE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int custom_x509write_csr_set_ns_cert_type(custom_x509write_csr *ctx,
                                           unsigned char ns_cert_type)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = custom_asn1_write_named_bitstring(&c, buf, &ns_cert_type, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = custom_x509write_csr_set_extension(ctx, CUSTOM_OID_NS_CERT_TYPE,
                                              CUSTOM_OID_SIZE(CUSTOM_OID_NS_CERT_TYPE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int x509write_csr_der_internal(custom_x509write_csr *ctx,
                                      unsigned char *buf,
                                      size_t size,
                                      unsigned char *sig, size_t sig_size,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng) // new_impl
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[CUSTOM_HASH_MAX_SIZE];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    custom_pk_type_t pk_alg;
#if defined(CUSTOM_USE_PSA_CRYPTO)
    size_t hash_len;
    psa_algorithm_t hash_alg = custom_hash_info_psa_from_md(ctx->md_alg);
#endif /* CUSTOM_USE_PSA_CRYPTO */

    /* Write the CSR backwards starting from the end of buf */
    c = buf + size;

    CUSTOM_ASN1_CHK_ADD(len, custom_x509_write_extensions(&c, buf,
                                                            ctx->extensions));

    if (len) {
        CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
        CUSTOM_ASN1_CHK_ADD(len,
                             custom_asn1_write_tag(
                                 &c, buf,
                                 CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE));

        CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
        CUSTOM_ASN1_CHK_ADD(len,
                             custom_asn1_write_tag(
                                 &c, buf,
                                 CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SET));

        CUSTOM_ASN1_CHK_ADD(len,
                             custom_asn1_write_oid(
                                 &c, buf, CUSTOM_OID_PKCS9_CSR_EXT_REQ,
                                 CUSTOM_OID_SIZE(CUSTOM_OID_PKCS9_CSR_EXT_REQ)));

        CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
        CUSTOM_ASN1_CHK_ADD(len,
                             custom_asn1_write_tag(
                                 &c, buf,
                                 CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE));
    }

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len,
                         custom_asn1_write_tag(
                             &c, buf,
                             CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_CONTEXT_SPECIFIC));

    CUSTOM_ASN1_CHK_ADD(pub_len, custom_pk_write_pubkey_der(ctx->key,
                                                              buf, c - buf));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    CUSTOM_ASN1_CHK_ADD(len, custom_x509_write_names(&c, buf,
                                                       ctx->subject));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_int(&c, buf, 0));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len,
                         custom_asn1_write_tag(
                             &c, buf,
                             CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE));

    /*
     * Sign the written CSR data into the sig buffer
     * Note: hash errors can happen only after an internal error
     */
    ret = custom_md(custom_md_info_from_type(ctx->md_alg), c, len, hash);
    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("x509write_csr_der_internal - hash", hash, CUSTOM_HASH_MAX_SIZE);
    #endif
    if (ret != 0) {
        return ret;
    }

    if ((ret = custom_pk_sign(ctx->key, ctx->md_alg, hash, CUSTOM_HASH_MAX_SIZE,
                               sig, sig_size, &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    if (custom_pk_can_do(ctx->key, CUSTOM_PK_ED25519)) {
        pk_alg = CUSTOM_PK_ED25519;
    } else {
        return CUSTOM_ERR_X509_INVALID_ALG;
    }

    if ((ret = custom_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     * Move the written CSR data to the start of buf to create space for
     * writing the signature into buf.
     */
    custom_memmove(buf, c, len);

    /*
     * Write sig and its OID into buf backwards from the end of buf.
     * Note: custom_x509_write_sig will check for c2 - ( buf + len ) < sig_len
     * and return CUSTOM_ERR_ASN1_BUF_TOO_SMALL if needed.
     */
    c2 = buf + size;
    CUSTOM_ASN1_CHK_ADD(sig_and_oid_len,
                         custom_x509_write_sig(&c2, buf + len, sig_oid, sig_oid_len,
                                                sig, sig_len));

    /*
     * Compact the space between the CSR data and signature by moving the
     * CSR data to the start of the signature.
     */
    c2 -= len;
    custom_memmove(c2, buf, len);

    /* ASN encode the total size and tag the CSR data with it. */
    len += sig_and_oid_len;
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c2, buf, len));
    CUSTOM_ASN1_CHK_ADD(len,
                         custom_asn1_write_tag(
                             &c2, buf,
                             CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE));

    /* Zero the unused bytes at the start of buf */
    custom_memset(buf, 0, c2 - buf);

    return (int) len;
}

int custom_x509write_csr_der(custom_x509write_csr *ctx, unsigned char *buf,
                              size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret;
    unsigned char *sig;

    if ((sig = custom_calloc(1, CUSTOM_PK_SIGNATURE_MAX_SIZE)) == NULL) {
        return CUSTOM_ERR_X509_ALLOC_FAILED;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509write_csr_der - calloc: %lu\n", CUSTOM_PK_SIGNATURE_MAX_SIZE);
    #endif

    ret = x509write_csr_der_internal(ctx, buf, size,
                                     sig, CUSTOM_PK_SIGNATURE_MAX_SIZE,
                                     f_rng, p_rng);

    custom_free(sig);

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_x509write_csr_der - free: %lu\n", CUSTOM_PK_SIGNATURE_MAX_SIZE);
    #endif

    return ret;
}

// custom new_impl
static int write_certs(unsigned char **p, const unsigned char *start, unsigned char *cert, int size){
    size_t len = 0;
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(p, start,
                                                            cert, size));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(p, start,
                                                        size));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(p, start,
                                                     CUSTOM_ASN1_OCTET_STRING));
    return (int) len;
}

int custom_x509write_csr_set_dice_certs(custom_x509write_csr *ctx, unsigned char *certs[], int *sizes) {
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    unsigned char buf[1024] = {0};

    unsigned char *c = buf + 1024;

    CUSTOM_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[2], sizes[2]));
    CUSTOM_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[1], sizes[1]));
    CUSTOM_ASN1_CHK_ADD(len, write_certs(&c, buf, certs[0], sizes[0]));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&c, buf, CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE));

    unsigned char *parsed_certs = buf;
    int dif_certs = 1024-len;
    parsed_certs += dif_certs;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("asn1 cert chain", parsed_certs, len);
    #endif
    
    ret = custom_x509write_csr_set_extension(ctx, CUSTOM_OID_DICE_CERTS, CUSTOM_OID_SIZE(CUSTOM_OID_DICE_CERTS),
        0, parsed_certs, len);

    return ret;
}

int custom_x509write_csr_set_nonce(custom_x509write_csr *ctx, unsigned char *nonce) {
    unsigned char buf[NONCE_LEN + 2] = { 0 };
    unsigned char *c;
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    
    c = buf + NONCE_LEN + 2;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(&c, buf, nonce, NONCE_LEN));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&c, buf, CUSTOM_ASN1_OCTET_STRING));

    if (len != (NONCE_LEN + 2)) {
        return ret;
    }

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("asn1 nonce", c, NONCE_LEN+2);
    #endif

    ret = custom_x509write_csr_set_extension(ctx, CUSTOM_OID_NONCE, CUSTOM_OID_SIZE(CUSTOM_OID_NONCE),
        0, c, (size_t) len);

    return ret;
}

int custom_x509write_csr_set_attestation_proof(custom_x509write_csr *ctx, unsigned char *attest_proof) {
    unsigned char buf[ATTESTATION_PROOF_LEN + 2] = { 0 };
    unsigned char *c;
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    
    c = buf + ATTESTATION_PROOF_LEN + 2;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(&c, buf, attest_proof, ATTESTATION_PROOF_LEN));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&c, buf, CUSTOM_ASN1_OCTET_STRING));

    if (len != (ATTESTATION_PROOF_LEN + 2)) {
        return ret;
    }

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("asn1 attest_proof", c, ATTESTATION_PROOF_LEN+2);
    #endif

    ret = custom_x509write_csr_set_extension(ctx, CUSTOM_OID_ATTESTATION_PROOF, CUSTOM_OID_SIZE(CUSTOM_OID_ATTESTATION_PROOF),
        0, c, (size_t) len);

    return ret;
}
