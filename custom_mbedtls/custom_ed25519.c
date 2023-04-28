#include "custom_functions.h"
#include "custom_string.h"

/*
static inline mbedtls_ed25519_context *mbedtls_pk_ed25519(const mbedtls_pk_context pk)
{
    switch (mbedtls_pk_get_type(&pk)) {
        case MBEDTLS_PK_ED25519:
            return (mbedtls_ed25519_context *) &((pk).pk_ctx);
        default:
            return NULL;
    }
}
*/

size_t ed25519_get_bitlen(const void *ctx)
{
    // const mbedtls_ed25519_context *rsa = (const mbedtls_ed25519_context *) ctx;
    return 8 * 32;
}

int ed25519_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ED25519;
}

void mbedtls_ed25519_init(mbedtls_ed25519_context *ctx)
{
    // memset(ctx, 0, sizeof(mbedtls_ed25519_context));
    // ctx->priv_key = mbedtls_calloc(0, 64);
    // ctx->pub_key = mbedtls_calloc(0, 32);

    // memset(ctx->priv_key, 0, 64);
    // memset(ctx->pub_key, 0, 32);
}

/*
void mbedtls_ed25519_context ed25519_alloc_wrap(void)
{
    //void *ctx = mbedtls_calloc(1, sizeof(mbedtls_ed25519_context));
    struct mbedtls_ed25519_context ctx;
    //memset(ctx, 0, sizeof(mbedtls_ed25519_context));
    //return ctx;
    //if (&ctx != NULL) {
        mbedtls_ed25519_init((mbedtls_ed25519_context *) &ctx);
    //}
    return ctx;
}
*/

void ed25519_free_wrap(void *ctx)
{
    mbedtls_ed25519_free((mbedtls_ed25519_context *)ctx);
    // mbedtls_free(ctx);
}

int ed25519_check_pair_wrap(const void *pub, const void *prv,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    /**
     * TO BE DONE
     * funzione che a partire da pub prende la coppia di chiavi pubblica privata, il seed contenuto in prv e genera
     * nuovamente la pubblica a partire dalla privata, ritornando 0 se matchano le due pubbliche
     */
    (void)f_rng;
    (void)p_rng;
    return mbedtls_ed25519_check_pub_priv(((mbedtls_ed25519_context *)pub)->priv_key,
                                          ((mbedtls_ed25519_context *)pub)->pub_key,
                                          (unsigned char *)prv);
}

int ed25519_encrypt_wrap(void *ctx,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    /**
     *
     * TO BE DONE
     *
     *
     */
    return 0;
}

int ed25519_decrypt_wrap(void *ctx,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{

    /**
     * TO BE DONE
     *
     *
     */
    return 0;
}

int mbedtls_ed25519_write_signature_restartable(mbedtls_ed25519_context *ctx,
                                                mbedtls_md_type_t md_alg,
                                                const unsigned char *hash, size_t hlen,
                                                unsigned char *sig, size_t sig_size, size_t *slen,
                                                int (*f_rng)(void *, unsigned char *, size_t),
                                                void *p_rng,
                                                mbedtls_ed25519_restart_ctx *rs_ctx)
{

    // ed25519_sign(app_sign, hash, sizeof(hash), ctx->pub_key, ctx->priv_key);
    // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    // unsigned char buf[64] = { 0 };
    // unsigned char *p = buf + sizeof(buf);
    // size_t len =  0;
    // unsigned char sign_no_tag[64];
    // ed25519_sign(sign_no_tag, hash, sizeof(hash), ctx->pub_key, ctx->priv_key);
    /*
    unsigned char* app_sign[64];
    unsigned char app_sign_test[] = {   0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                                    0x0, 0x1, 0x2, 0x3
                                };
                                /*
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf,
                                                            (const unsigned char *) sign_no_tag, sizeof(sign_no_tag)));
    //MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    //MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_BIT_STRING));
    /*
    if (len > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    */

    // my_memcpy(sig, p, len);
    /*
    printf("FIRMA OID\n");
    for(int i =0; i <*slen; i ++){
        printf("%02x-",sig[i]);
    }
    printf("\n");
    */
    ed25519_sign(sig, hash, sizeof(hash), ctx->pub_key, ctx->priv_key);
    *slen = 64;
    return 0;
}

int mbedtls_ed25519_write_signature(mbedtls_ed25519_context *ctx,
                                    mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hlen,
                                    unsigned char *sig, size_t sig_size, size_t *slen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    return mbedtls_ed25519_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
}

int ed25519_sign_wrap(void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t sig_size, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ed25519_write_signature((mbedtls_ed25519_context *)ctx,
                                           md_alg, hash, hash_len,
                                           sig, sig_size, sig_len,
                                           f_rng, p_rng);
}

int ed25519_verify_wrap(void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len)
{
    mbedtls_ed25519_context *ed25519 = (mbedtls_ed25519_context *)ctx;
    // ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key)

    return ed25519_verify(sig, hash, sizeof(hash), ed25519->pub_key);
    // return 0;
}

int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519)
{

    for (int i = 0; i < 32; i++)
    {
        ed25519->pub_key[i] = (*p)[i];
    }
    ed25519->len = 32;
    /*
    printf("Stampa dopo inserimento pubblica interno\n");
    for(int i =0; i <32; i ++){
        printf("%02x",ed25519->pub_key[i]);
    }
    printf("\n");
    */
    return 0;
}

int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519)
{

    for (int i = 0; i < 64; i++)
    {
        ed25519->priv_key[i] = (*p)[i];
    }
    ed25519->len = 64;
    /*
    printf("Stampa dopo inserimento privata interno\n");
    for(int i =0; i <64; i ++){
        printf("%02x",ed25519->priv_key[i]);
    }
    printf("\n");
    */
    return 0;
}

void mbedtls_ed25519_free(mbedtls_ed25519_context *ctx)
{
    if (ctx == NULL)
    {
        return;
    }
    // mbedtls_free(ctx->priv_key);
    // mbedtls_free(ctx->pub_key);
}

int mbedtls_ed25519_check_pub_priv(unsigned char *priv, unsigned char *pub, unsigned char *seed)
{

    unsigned char result[32];
    // ed25519_create keypair(seed, priv, result);
    for (int i = 0; i < 32; i++)
    {
        if (result[i] != pub[i])
            return 1;
    }
    return 0;
}

int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context ed25519)
{

    // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 32;
    unsigned char buf[32];
    /*
    printf("Chiave pubblica\n");
    for(int i =0; i <32; i ++){
        printf("%02x",ed25519->pub_key[i]);
    }
    */

    for (int i = 0; i < 32; i++)
    {
        buf[i] = ed25519.pub_key[i];
    }

    /*
    printf("Chiave pubblica\n");
    for(int i =0; i <32; i ++){
        printf("%02x",buf[i]);
    }

   printf("\n");
    */
    if (*p < start || (size_t)(*p - start) < len)
    {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    *p -= len;

    my_memcpy(*p, buf, len);
    return (int)len;
}
