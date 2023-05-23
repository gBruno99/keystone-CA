#include "custom_functions.h"

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

    // mbedtls_platform_zeroize(ctx, sizeof(mbedtls_pk_context));
    my_memset(ctx, 0x00, sizeof(mbedtls_pk_context));
}

const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type) // new_impl
{
    switch (pk_type)
    {
    case MBEDTLS_PK_ED25519:
        return &mbedtls_ed25519_info;
    default:
        return NULL;
    }
}

int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info)
{
    if (info == NULL || ctx->pk_info != NULL) {
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("PK - pk setup: err 1\n");
        #endif
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL) {
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("PK - pk setup: err 2\n");
        #endif
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}

int mbedtls_pk_can_do(const mbedtls_pk_context *ctx, mbedtls_pk_type_t type)
{
    /* A context with null pk_info is not set up yet and can't do anything.
     * For backward compatibility, also accept NULL instead of a context
     * pointer. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->can_do(type);
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

int mbedtls_pk_verify_restartable(mbedtls_pk_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  const unsigned char *sig, size_t sig_len,
                                  mbedtls_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL ||
        pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if (rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->verify_rs_func != NULL) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if ((ret = pk_restart_setup(rs_ctx, ctx->pk_info)) != 0) {
            return ret;
        }

        ret = ctx->pk_info->verify_rs_func(ctx->pk_ctx,
                                           md_alg, hash, hash_len, sig, sig_len, rs_ctx->rs_ctx);

        if (ret != MBEDTLS_ERR_ECP_IN_PROGRESS) {
            mbedtls_pk_restart_free(rs_ctx);
        }

        return ret;
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    if (ctx->pk_info->verify_func == NULL) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len);
}

int mbedtls_pk_verify(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len)
{
    return mbedtls_pk_verify_restartable(ctx, md_alg, hash, hash_len,
                                         sig, sig_len, NULL);
}

int mbedtls_pk_verify_ext(mbedtls_pk_type_t type, const void *options,
                          mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len)
{
    if ((md_alg != MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (!mbedtls_pk_can_do(ctx, type)) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    if (type != MBEDTLS_PK_RSASSA_PSS) {
        /* General case: no options */
        if (options != NULL) {
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }

        return mbedtls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
    }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_pk_rsassa_pss_options *pss_opts;

    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (options == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (pss_opts->mgf1_hash_id == md_alg) {
        unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
        unsigned char *p;
        int key_len;
        size_t signature_length;
        psa_status_t status = PSA_ERROR_DATA_CORRUPT;
        psa_status_t destruction_status = PSA_ERROR_DATA_CORRUPT;

        psa_algorithm_t psa_md_alg = mbedtls_hash_info_psa_from_md(md_alg);
        mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_algorithm_t psa_sig_alg = PSA_ALG_RSA_PSS_ANY_SALT(psa_md_alg);
        p = buf + sizeof(buf);
        key_len = mbedtls_pk_write_pubkey(&p, buf, ctx);

        if (key_len < 0) {
            return key_len;
        }

        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&attributes, psa_sig_alg);

        status = psa_import_key(&attributes,
                                buf + sizeof(buf) - key_len, key_len,
                                &key_id);
        if (status != PSA_SUCCESS) {
            psa_destroy_key(key_id);
            return PSA_PK_TO_MBEDTLS_ERR(status);
        }

        /* This function requires returning MBEDTLS_ERR_PK_SIG_LEN_MISMATCH
         * on a valid signature with trailing data in a buffer, but
         * mbedtls_psa_rsa_verify_hash requires the sig_len to be exact,
         * so for this reason the passed sig_len is overwritten. Smaller
         * signature lengths should not be accepted for verification. */
        signature_length = sig_len > mbedtls_pk_get_len(ctx) ?
                           mbedtls_pk_get_len(ctx) : sig_len;
        status = psa_verify_hash(key_id, psa_sig_alg, hash,
                                 hash_len, sig, signature_length);
        destruction_status = psa_destroy_key(key_id);

        if (status == PSA_SUCCESS && sig_len > mbedtls_pk_get_len(ctx)) {
            return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
        }

        if (status == PSA_SUCCESS) {
            status = destruction_status;
        }

        return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    } else
#endif
    {
        if (sig_len < mbedtls_pk_get_len(ctx)) {
            return MBEDTLS_ERR_RSA_VERIFY_FAILED;
        }

        ret = mbedtls_rsa_rsassa_pss_verify_ext(mbedtls_pk_rsa(*ctx),
                                                md_alg, (unsigned int) hash_len, hash,
                                                pss_opts->mgf1_hash_id,
                                                pss_opts->expected_salt_len,
                                                sig);
        if (ret != 0) {
            return ret;
        }

        if (sig_len > mbedtls_pk_get_len(ctx)) {
            return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
        }

        return 0;
    }
#else
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
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

    /* // new_impl
    if (ctx->pk_info == NULL || pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    */
    (void)rs_ctx; // if(false)

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

size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx)
{
    /* For backward compatibility, accept NULL or a context that
     * isn't set up yet, and return a fake value that should be safe. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->get_bitlen(ctx->pk_ctx);
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

    my_memset(params, 0, sizeof(mbedtls_asn1_buf));

    if ((ret = mbedtls_asn1_get_alg(p, end, &alg_oid, params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_ALG, ret);
    }

    *pk_alg = MBEDTLS_PK_ED25519; // new_impl
    /*
    if (mbedtls_oid_get_pk_alg(&alg_oid, pk_alg) != 0) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
    */

    /*
     * No parameters with RSA (only for EC)
     */
    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
         params->len != 0)) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("pk_get_pk_alg\n");
    #endif
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

    // new_impl
    ret = pk_set_ed25519pubkey(p, mbedtls_pk_ed25519(*pk));
    // ret = pk_set_ed25519pubkey(&p, &ctx->pk_ctx );//mbedtls_pk_ed25519(*ctx));
    *p += 32;

    if (ret == 0 && *p != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0) {
        mbedtls_pk_free(pk);
    }

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_pk_parse_subpubkey - %s\n", pk->pk_info->name);
    print_hex_string("mbedtls_pk_parse_subpubkey - pk",mbedtls_pk_ed25519(*pk)->pub_key, PUBLIC_KEY_SIZE);
    #endif 
    return ret;
}

int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen, int type_k) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
    const mbedtls_pk_info_t *pk_info;
    if (keylen == 0) {
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("PK - parse pk: err 1\n");
        #endif
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ED25519)) == NULL) {
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("PK - parse pk: err 2\n");
        #endif
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if(ctx->pk_info != NULL && ctx->pk_info != pk_info) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL && (ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
        #if MBEDTLS_DEBUG_PRINTS
        my_printf("PK - parse pk: err 3\n");
        #endif
        return ret;
    }

    p = (unsigned char *)key;

    if (type_k == 0) {
        pk_set_ed25519pubkey(&p, mbedtls_pk_ed25519(*ctx));
        /*for(int i = 0; i < 32; i++){
            ctx->pk_ctx->pub_key[i] = p[i];
        }
        ctx->pk_ctx->len = 32;*/
    }
    else
        pk_set_ed25519privkey(&p, mbedtls_pk_ed25519(*ctx));
    return 0;
}

// pkwrite.c
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const mbedtls_pk_context *key) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_ED25519) {
        MBEDTLS_ASN1_CHK_ADD(len, pk_write_ed25519_pubkey(p, start, *mbedtls_pk_ed25519(*key)));
    } else
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;


    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_pk_write_pubkey - len = %d\n", len);
    #endif

    return (int) len;
}

int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size) // new_impl
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    // mbedtls_pk_type_t pk_type;
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

    // pk_type = mbedtls_pk_get_type(key);

    oid = "{0x2B, 0x65, 0x70}";
    oid_len = 3;
    /*
    if ((ret = mbedtls_oid_get_oid_by_pk_alg(pk_type, &oid,
                                             &oid_len)) != 0) {
        return ret;
    }
    */

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, buf, oid, oid_len,
                                                                      par_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    #if MBEDTLS_DEBUG_PRINTS
    my_printf("mbedtls_pk_write_pubkey_der - len = %d\n", len);
    #endif
    return (int) len;
}

