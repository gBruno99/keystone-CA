#include "custom_functions.h"

const custom_pk_info_t custom_ed25519_info = { //new_impl
    CUSTOM_PK_ED25519,
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
void custom_pk_init(custom_pk_context *ctx)
{
    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

void custom_pk_free(custom_pk_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->pk_info != NULL) {
        ctx->pk_info->ctx_free_func(ctx->pk_ctx);
    }

    custom_platform_zeroize(ctx, sizeof(custom_pk_context));
}

const custom_pk_info_t *custom_pk_info_from_type(custom_pk_type_t pk_type) // new_impl
{
    switch (pk_type)
    {
    case CUSTOM_PK_ED25519:
        return &custom_ed25519_info;
    default:
        return NULL;
    }
}

int custom_pk_setup(custom_pk_context *ctx, const custom_pk_info_t *info)
{
    if (info == NULL || ctx->pk_info != NULL) {
        #if CUSTOM_DEBUG_PRINTS
        printf("PK - pk setup: err 1\n");
        #endif
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL) {
        #if CUSTOM_DEBUG_PRINTS
        printf("PK - pk setup: err 2\n");
        #endif
        return CUSTOM_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}

int custom_pk_can_do(const custom_pk_context *ctx, custom_pk_type_t type)
{
    /* A context with null pk_info is not set up yet and can't do anything.
     * For backward compatibility, also accept NULL instead of a context
     * pointer. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->can_do(type);
}

static inline int pk_hashlen_helper(custom_md_type_t md_alg, size_t *hash_len)
{
    if (*hash_len != 0) {
        return 0;
    }

    *hash_len = custom_hash_info_get_size(md_alg);

    if (*hash_len == 0) {
        return -1;
    }

    return 0;
}

int custom_pk_verify_restartable(custom_pk_context *ctx,
                                  custom_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  const unsigned char *sig, size_t sig_len,
                                  custom_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != CUSTOM_MD_NONE || hash_len != 0) && hash == NULL) {
        printf("custom_pk_verify_restartable - exit 1\n");
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL ||
        pk_hashlen_helper(md_alg, &hash_len) != 0) {
        printf("custom_pk_verify_restartable - exit 2\n");
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    (void) rs_ctx;

    if (ctx->pk_info->verify_func == NULL) {
        printf("custom_pk_verify_restartable - exit 3\n");
        return CUSTOM_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len);
}

int custom_pk_verify(custom_pk_context *ctx, custom_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len)
{
    return custom_pk_verify_restartable(ctx, md_alg, hash, hash_len,
                                         sig, sig_len, NULL);
}

int custom_pk_verify_ext(custom_pk_type_t type, const void *options,
                          custom_pk_context *ctx, custom_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len)
{
    if ((md_alg != CUSTOM_MD_NONE || hash_len != 0) && hash == NULL) {
        printf("custom_pk_verify_ext - exit 1\n");
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL) {
        printf("custom_pk_verify_ext - exit 2\n");
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    if (!custom_pk_can_do(ctx, type)) {
        printf("custom_pk_verify_ext - exit 3\n");
        return CUSTOM_ERR_PK_TYPE_MISMATCH;
    }

    if (type != CUSTOM_PK_RSASSA_PSS) {
        /* General case: no options */
        if (options != NULL) {
            printf("custom_pk_verify_ext - exit 4\n");
            return CUSTOM_ERR_PK_BAD_INPUT_DATA;
        }

        return custom_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
    }
    printf("custom_pk_verify_ext - exit 5\n");
    return CUSTOM_ERR_PK_FEATURE_UNAVAILABLE;
}

int custom_pk_sign_restartable(custom_pk_context *ctx,
                                custom_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                custom_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != CUSTOM_MD_NONE || hash_len != 0) && hash == NULL) {
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    /* // new_impl
    if (ctx->pk_info == NULL || pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }
    */
    (void)rs_ctx; // if(false)

    if (ctx->pk_info->sign_func == NULL) {
        return CUSTOM_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->sign_func(ctx->pk_ctx, md_alg,
                                   hash, hash_len,
                                   sig, sig_size, sig_len,
                                   f_rng, p_rng);
}

int custom_pk_sign(custom_pk_context *ctx, custom_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return custom_pk_sign_restartable(ctx, md_alg, hash, hash_len,
                                       sig, sig_size, sig_len,
                                       f_rng, p_rng, NULL);
}

size_t custom_pk_get_bitlen(const custom_pk_context *ctx)
{
    /* For backward compatibility, accept NULL or a context that
     * isn't set up yet, and return a fake value that should be safe. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->get_bitlen(ctx->pk_ctx);
}

custom_pk_type_t custom_pk_get_type(const custom_pk_context *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL) {
        return CUSTOM_PK_NONE;
    }

    return ctx->pk_info->type;
}

// pkparse.c
static int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         custom_pk_type_t *pk_alg, custom_asn1_buf *params)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    custom_asn1_buf alg_oid;

    custom_memset(params, 0, sizeof(custom_asn1_buf));

    if ((ret = custom_asn1_get_alg(p, end, &alg_oid, params)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_PK_INVALID_ALG, ret);
    }

    *pk_alg = CUSTOM_PK_ED25519; // new_impl
    /*
    if (custom_oid_get_pk_alg(&alg_oid, pk_alg) != 0) {
        return CUSTOM_ERR_PK_UNKNOWN_PK_ALG;
    }
    */

    /*
     * No parameters with RSA (only for EC)
     */
    if (*pk_alg == CUSTOM_PK_RSA &&
        ((params->tag != CUSTOM_ASN1_NULL && params->tag != 0) ||
         params->len != 0)) {
        return CUSTOM_ERR_PK_INVALID_ALG;
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("pk_get_pk_alg\n");
    #endif
    return 0;
}

int custom_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               custom_pk_context *pk)
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    custom_asn1_buf alg_params;
    custom_pk_type_t pk_alg = CUSTOM_PK_NONE;
    const custom_pk_info_t *pk_info;

    if ((ret = custom_asn1_get_tag(p, end, &len,
                                    CUSTOM_ASN1_CONSTRUCTED | CUSTOM_ASN1_SEQUENCE)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params)) != 0) {
        return ret;
    }

    if ((ret = custom_asn1_get_bitstring_null(p, end, &len)) != 0) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_PK_INVALID_PUBKEY, ret);
    }

    if (*p + len != end) {
        return CUSTOM_ERROR_ADD(CUSTOM_ERR_PK_INVALID_PUBKEY,
                                 CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((pk_info = custom_pk_info_from_type(pk_alg)) == NULL) {
        return CUSTOM_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = custom_pk_setup(pk, pk_info)) != 0) {
        return ret;
    }

    // new_impl
    ret = pk_set_ed25519pubkey(p, custom_pk_ed25519(*pk));
    // ret = pk_set_ed25519pubkey(&p, &ctx->pk_ctx );//custom_pk_ed25519(*ctx));
    *p += 32;

    if (ret == 0 && *p != end) {
        ret = CUSTOM_ERROR_ADD(CUSTOM_ERR_PK_INVALID_PUBKEY,
                                CUSTOM_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0) {
        custom_pk_free(pk);
    }

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_pk_parse_subpubkey - %s\n", pk->pk_info->name);
    print_hex_string("custom_pk_parse_subpubkey - pk",custom_pk_ed25519(*pk)->pub_key, PUBLIC_KEY_SIZE);
    #endif 
    return ret;
}

int custom_pk_parse_public_key(custom_pk_context *ctx,
                                const unsigned char *key, size_t keylen, int type_k) // new_impl
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
    const custom_pk_info_t *pk_info;
    if (keylen == 0) {
        #if CUSTOM_DEBUG_PRINTS
        printf("PK - parse pk: err 1\n");
        #endif
        return CUSTOM_ERR_PK_KEY_INVALID_FORMAT;
    }

    if ((pk_info = custom_pk_info_from_type(CUSTOM_PK_ED25519)) == NULL) {
        #if CUSTOM_DEBUG_PRINTS
        printf("PK - parse pk: err 2\n");
        #endif
        return CUSTOM_ERR_PK_UNKNOWN_PK_ALG;
    }

    if(ctx->pk_info != NULL && ctx->pk_info != pk_info) {
        return CUSTOM_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL && (ret = custom_pk_setup(ctx, pk_info)) != 0) {
        #if CUSTOM_DEBUG_PRINTS
        printf("PK - parse pk: err 3\n");
        #endif
        return ret;
    }

    p = (unsigned char *)key;

    if (type_k == 0) {
        pk_set_ed25519pubkey(&p, custom_pk_ed25519(*ctx));
        /*for(int i = 0; i < 32; i++){
            ctx->pk_ctx->pub_key[i] = p[i];
        }
        ctx->pk_ctx->len = 32;*/
    }
    else
        pk_set_ed25519privkey(&p, custom_pk_ed25519(*ctx));
    return 0;
}

// pkwrite.c
int custom_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const custom_pk_context *key) // new_impl
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (custom_pk_get_type(key) == CUSTOM_PK_ED25519) {
        CUSTOM_ASN1_CHK_ADD(len, pk_write_ed25519_pubkey(p, start, *custom_pk_ed25519(*key)));
    } else
        return CUSTOM_ERR_PK_FEATURE_UNAVAILABLE;


    #if CUSTOM_DEBUG_PRINTS
    printf("custom_pk_write_pubkey - len = %d\n", len);
    #endif

    return (int) len;
}

int custom_pk_write_pubkey_der(const custom_pk_context *key, unsigned char *buf, size_t size) // new_impl
{
    int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    // custom_pk_type_t pk_type;
    const char *oid;

    if (size == 0) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

    CUSTOM_ASN1_CHK_ADD(len, custom_pk_write_pubkey(&c, buf, key));

    if (c - buf < 1) {
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&c, buf, CUSTOM_ASN1_BIT_STRING));

    // pk_type = custom_pk_get_type(key);

    oid = "{0x2B, 0x65, 0x70}";
    oid_len = 3;
    /*
    if ((ret = custom_oid_get_oid_by_pk_alg(pk_type, &oid,
                                             &oid_len)) != 0) {
        return ret;
    }
    */

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_algorithm_identifier(&c, buf, oid, oid_len,
                                                                      par_len));

    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&c, buf, len));
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&c, buf, CUSTOM_ASN1_CONSTRUCTED |
                                                     CUSTOM_ASN1_SEQUENCE));

    #if CUSTOM_DEBUG_PRINTS
    printf("custom_pk_write_pubkey_der - len = %d\n", len);
    #endif
    return (int) len;
}

