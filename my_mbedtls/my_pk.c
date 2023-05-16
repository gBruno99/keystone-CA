const mbedtls_pk_info_t mbedtls_ed25519_info = { //new_impl
    MBEDTLS_PK_ED25519,
    "ED25519",
    ed25519_get_bitlen,
    ed25519_can_do,
    ed25519_verify_wrap,
    ed25519_sign_wrap,
    ed25519_decrypt_wrap,
    ed25519_encrypt_wrap,
    ed25519_check_pair_wrap,
    ed25519_alloc_wrap,
    ed25519_free_wrap,
};

// pk.c
void mbedtls_pk_init(mbedtls_pk_context *ctx)
{
    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

void mbedtls_pk_free(mbedtls_pk_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->pk_info != NULL) {
        ctx->pk_info->ctx_free_func(ctx->pk_ctx);
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_pk_context));
}

const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type)
{
    switch (pk_type) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return &mbedtls_rsa_info;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_LIGHT)
        case MBEDTLS_PK_ECKEY:
            return &mbedtls_eckey_info;
        case MBEDTLS_PK_ECKEY_DH:
            return &mbedtls_eckeydh_info;
#endif /* MBEDTLS_ECP_LIGHT */
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
        case MBEDTLS_PK_ECDSA:
            return &mbedtls_ecdsa_info;
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return NULL;
    }
}

int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info)
{
    if (info == NULL || ctx->pk_info != NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}

static inline int pk_hashlen_helper(mbedtls_md_type_t md_alg, size_t *hash_len)
{
    if (*hash_len != 0) {
        return 0;
    }

    *hash_len = mbedtls_hash_info_get_size(md_alg);

    if (*hash_len == 0) {
        return -1;
    }

    return 0;
}

int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL || pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if (rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->sign_rs_func != NULL) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if ((ret = pk_restart_setup(rs_ctx, ctx->pk_info)) != 0) {
            return ret;
        }

        ret = ctx->pk_info->sign_rs_func(ctx->pk_ctx, md_alg,
                                         hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng, rs_ctx->rs_ctx);

        if (ret != MBEDTLS_ERR_ECP_IN_PROGRESS) {
            mbedtls_pk_restart_free(rs_ctx);
        }

        return ret;
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    if (ctx->pk_info->sign_func == NULL) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->sign_func(ctx->pk_ctx, md_alg,
                                   hash, hash_len,
                                   sig, sig_size, sig_len,
                                   f_rng, p_rng);
}

int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_pk_sign_restartable(ctx, md_alg, hash, hash_len,
                                       sig, sig_size, sig_len,
                                       f_rng, p_rng, NULL);
}

mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL) {
        return MBEDTLS_PK_NONE;
    }

    return ctx->pk_info->type;
}

// pkparse.c
static int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf alg_oid;

    memset(params, 0, sizeof(mbedtls_asn1_buf));

    if ((ret = mbedtls_asn1_get_alg(p, end, &alg_oid, params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_ALG, ret);
    }

    if (mbedtls_oid_get_pk_alg(&alg_oid, pk_alg) != 0) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    /*
     * No parameters with RSA (only for EC)
     */
    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
         params->len != 0)) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    return 0;
}

int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               mbedtls_pk_context *pk)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY, ret);
    }

    if (*p + len != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
        return ret;
    }

#if defined(MBEDTLS_RSA_C)
    if (pk_alg == MBEDTLS_PK_RSA) {
        ret = pk_get_rsapubkey(p, end, mbedtls_pk_rsa(*pk));
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_LIGHT)
    if (pk_alg == MBEDTLS_PK_ECKEY_DH || pk_alg == MBEDTLS_PK_ECKEY) {
        ret = pk_use_ecparams(&alg_params, &mbedtls_pk_ec(*pk)->grp);
        if (ret == 0) {
            ret = pk_get_ecpubkey(p, end, mbedtls_pk_ec(*pk));
        }
    } else
#endif /* MBEDTLS_ECP_LIGHT */
    ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    if (ret == 0 && *p != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0) {
        mbedtls_pk_free(pk);
    }

    return ret;
}

int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
#if defined(MBEDTLS_RSA_C)
    const mbedtls_pk_info_t *pk_info;
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init(&pem);
#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      "-----BEGIN RSA PUBLIC KEY-----",
                                      "-----END RSA PUBLIC KEY-----",
                                      key, NULL, 0, &len);
    }

    if (ret == 0) {
        p = pem.buf;
        if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == NULL) {
            mbedtls_pem_free(&pem);
            return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
        }

        if ((ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
            mbedtls_pem_free(&pem);
            return ret;
        }

        if ((ret = pk_get_rsapubkey(&p, p + pem.buflen, mbedtls_pk_rsa(*ctx))) != 0) {
            mbedtls_pk_free(ctx);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        mbedtls_pem_free(&pem);
        return ret;
    }
#endif /* MBEDTLS_RSA_C */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      "-----BEGIN PUBLIC KEY-----",
                                      "-----END PUBLIC KEY-----",
                                      key, NULL, 0, &len);
    }

    if (ret == 0) {
        /*
         * Was PEM encoded
         */
        p = pem.buf;

        ret = mbedtls_pk_parse_subpubkey(&p,  p + pem.buflen, ctx);
        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        mbedtls_pem_free(&pem);
        return ret;
    }
    mbedtls_pem_free(&pem);
#endif /* MBEDTLS_PEM_PARSE_C */

#if defined(MBEDTLS_RSA_C)
    if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
        return ret;
    }

    p = (unsigned char *) key;
    ret = pk_get_rsapubkey(&p, p + keylen, mbedtls_pk_rsa(*ctx));
    if (ret == 0) {
        return ret;
    }
    mbedtls_pk_free(ctx);
    if (ret != (MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                  MBEDTLS_ERR_ASN1_UNEXPECTED_TAG))) {
        return ret;
    }
#endif /* MBEDTLS_RSA_C */
    p = (unsigned char *) key;

    ret = mbedtls_pk_parse_subpubkey(&p, p + keylen, ctx);

    return ret;
}

// pkwrite.c
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const mbedtls_pk_context *key)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

#if defined(MBEDTLS_RSA_C)
    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_RSA) {
        MBEDTLS_ASN1_CHK_ADD(len, pk_write_rsa_pubkey(p, start, mbedtls_pk_rsa(*key)));
    } else
#endif
#if defined(MBEDTLS_ECP_LIGHT)
    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_ECKEY) {
        MBEDTLS_ASN1_CHK_ADD(len, pk_write_ec_pubkey(p, start, mbedtls_pk_ec(*key)));
    } else
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_OPAQUE) {
        size_t buffer_size;
        mbedtls_svc_key_id_t *key_id = (mbedtls_svc_key_id_t *) key->pk_ctx;

        if (*p < start) {
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }

        buffer_size = (size_t) (*p - start);
        if (psa_export_public_key(*key_id, start, buffer_size, &len)
            != PSA_SUCCESS) {
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        } else {
            *p -= len;
            memmove(*p, start, len);
        }
    } else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;

    return (int) len;
}

int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    mbedtls_pk_type_t pk_type;
    const char *oid;

    if (size == 0) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_pk_write_pubkey(&c, buf, key));

    if (c - buf < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_BIT_STRING));

    pk_type = mbedtls_pk_get_type(key);
#if defined(MBEDTLS_ECP_LIGHT)
    if (pk_type == MBEDTLS_PK_ECKEY) {
        MBEDTLS_ASN1_CHK_ADD(par_len, pk_write_ec_param(&c, buf, mbedtls_pk_ec(*key)));
    }
#endif /* MBEDTLS_ECP_LIGHT */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (pk_type == MBEDTLS_PK_OPAQUE) {
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_type_t key_type;
        mbedtls_svc_key_id_t key_id;
        psa_ecc_family_t curve;
        size_t bits;

        key_id = *((mbedtls_svc_key_id_t *) key->pk_ctx);
        if (PSA_SUCCESS != psa_get_key_attributes(key_id, &attributes)) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
        key_type = psa_get_key_type(&attributes);
        bits = psa_get_key_bits(&attributes);
        psa_reset_key_attributes(&attributes);

        if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
            curve = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
            if (curve == 0) {
                return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
            }

            ret = mbedtls_psa_get_ecc_oid_from_id(curve, bits,
                                                  &oid, &oid_len);
            if (ret != 0) {
                return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
            }

            /* Write EC algorithm parameters; that's akin
             * to pk_write_ec_param() above. */
            MBEDTLS_ASN1_CHK_ADD(par_len, mbedtls_asn1_write_oid(&c, buf,
                                                                 oid,
                                                                 oid_len));

            /* The rest of the function works as for legacy EC contexts. */
            pk_type = MBEDTLS_PK_ECKEY;
        } else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
            /* The rest of the function works as for legacy RSA contexts. */
            pk_type = MBEDTLS_PK_RSA;
        } else {
            return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        }
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if ((ret = mbedtls_oid_get_oid_by_pk_alg(pk_type, &oid,
                                             &oid_len)) != 0) {
        return ret;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, buf, oid, oid_len,
                                                                      par_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

