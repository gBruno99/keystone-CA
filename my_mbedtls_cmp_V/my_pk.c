const mbedtls_pk_info_t mbedtls_ed25519_info = {
    MBEDTLS_PK_ED25519,
    "ED25519",
    ed25519_get_bitlen,
    ed25519_can_do,
    ed25519_verify_wrap,
    ed25519_sign_wrap,
    ed25519_decrypt_wrap,
    ed25519_encrypt_wrap,
    ed25519_check_pair_wrap,
    // ed25519_alloc_wrap,
    ed25519_free_wrap,
};

// pk.c
void mbedtls_pk_init(mbedtls_pk_context *ctx)
{
    ctx->pk_info = NULL;
    // ctx->pk_ctx = NULL;
}

void mbedtls_pk_free(mbedtls_pk_context *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    if (ctx->pk_info != NULL)
    {
        ctx->pk_info->ctx_free_func(&(ctx->pk_ctx));
    }

    // mbedtls_platform_zeroize(ctx, sizeof(mbedtls_pk_context));
}

const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type)
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
    /**
    if (info == NULL || ctx->pk_info != NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }*/
    // ctx->pk_ctx = info->ctx_alloc_func();
    ctx->pk_info = info;

    return 0;
}

static inline int pk_hashlen_helper(mbedtls_md_type_t md_alg, size_t *hash_len)
{
    if (*hash_len != 0)
    {
        return 0;
    }

    *hash_len = mbedtls_hash_info_get_size(md_alg);

    if (*hash_len == 0)
    {
        return -1;
    }

    return 0;
}

int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
// mbedtls_pk_restart_ctx *rs_ctx)
{

    if ((md_alg != MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL)
    {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    /*
    if (ctx->pk_info == NULL || pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }*/

    if (ctx->pk_info->sign_func == NULL)
    {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->sign_func(&(ctx->pk_ctx), md_alg,
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
                                       f_rng, p_rng); //, NULL);
}

mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)
{
    /*
    if (ctx == NULL || ctx->pk_info == NULL) {
        return MBEDTLS_PK_NONE;
    }*/

    return ctx->pk_info->type;
}

// pkparse.c
int pk_get_pk_alg(unsigned char **p,
                  const unsigned char *end,
                  mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf alg_oid;

    my_memset(params, 0, sizeof(mbedtls_asn1_buf));

    if ((ret = mbedtls_asn1_get_alg(p, end, &alg_oid, params)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_ALG, ret);
    }

    *pk_alg = MBEDTLS_PK_ED25519;
    /*
    if (mbedtls_oid_get_pk_alg(&alg_oid, pk_alg) != 0) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
\   */
    /*
     * No parameters with RSA (only for EC)
     */
    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
         params->len != 0))
    {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    return 0;
}

int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, mbedtls_pk_context *pk)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = *p + len;
    // pk_alg = MBEDTLS_PK_ED25519;

    if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params)) != 0)
    {
        return ret;
    }

    // end = *p - 32;
    // len = 32;
    //*p = *p -32;

    if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != 0)
    { // funzione che estrae la chiave pubblica
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY, ret);
    }

    if (*p + len != end)
    {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL)
    {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0)
    {
        return ret;
    }

    ret = pk_set_ed25519pubkey(p, &pk->pk_ctx); // mbedtls_pk_ed25519(*pk));
    // ret = pk_set_ed25519pubkey(&p, &ctx->pk_ctx );//mbedtls_pk_ed25519(*ctx));

    *p += 32;
    if (ret == 0 && *p != end)
    {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0)
    {
        mbedtls_pk_free(pk);
    }

    return ret;
}

int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, int type_k)
{

    // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
    const mbedtls_pk_info_t *pk_info;
    if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ED25519)) == NULL)
    {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
    // assegna semplicemente il tipo di pk_info ritornato dalla funzione precedente a quello contenuto in ctx
    //  ctx->pk_info = pk_info;
    /*
    if ((ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
        return ret;
    }*/
    // mbedtls_ed25519_context pk_ctx;
    // mbedtls_ed25519_context *pk_ctx_point = &pk_ctx;
    // ctx->pk_ctx = pk_ctx_point;
    ctx->pk_info = pk_info;

    p = (unsigned char *)key;

    if (type_k == 0)
    {
        pk_set_ed25519pubkey(&p, &ctx->pk_ctx); // mbedtls_pk_ed25519(*ctx));
        /*for(int i = 0; i < 32; i++){
            ctx->pk_ctx->pub_key[i] = p[i];
        }
        ctx->pk_ctx->len = 32;*/
    }
    else
        pk_set_ed25519privkey(&p, &ctx->pk_ctx); // mbedtls_pk_ed25519(*ctx));
    return 0;
}

// pkwrite.c
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start, const mbedtls_pk_context *key)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    MBEDTLS_ASN1_CHK_ADD(len, pk_write_ed25519_pubkey(p, start, key->pk_ctx));

    return (int)len;
}

int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    // mbedtls_pk_type_t pk_type;
    const char *oid;

    if (size == 0)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_pk_write_pubkey(&c, buf, key));

    if (c - buf < 1)
    {
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

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, buf, oid, oid_len,
                                                                      par_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return (int)len;
}
