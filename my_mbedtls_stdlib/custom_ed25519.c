#include "custom_functions.h"
#include "ed25519/ed25519.h"

custom_ed25519_context *custom_pk_ed25519(const custom_pk_context pk)
{
    switch (custom_pk_get_type(&pk))
    {
    case CUSTOM_PK_ED25519:
        return (custom_ed25519_context *)(pk.pk_ctx);
    default:
        return NULL;
    }
}

void custom_ed25519_init(custom_ed25519_context *ctx)
{
    custom_memset(ctx, 0, sizeof(custom_ed25519_context));
    ctx->no_priv_key = 1;
    // ctx->priv_key = custom_calloc(1, PRIVATE_KEY_SIZE);
    // ctx->pub_key = custom_calloc(1, PUBLIC_KEY_SIZE);
    // if((ctx->priv_key==NULL)||(ctx->pub_key==NULL))
    //     return;
    // memset(ctx->priv_key, 0, PRIVATE_KEY_SIZE);
    // memset(ctx->pub_key, 0, PUBLIC_KEY_SIZE);
}

void custom_ed25519_free(custom_ed25519_context *ctx)
{
    if (ctx == NULL)
    {
        return;
    }
    // custom_free(ctx->priv_key);
    // custom_free(ctx->pub_key);
}

int pk_set_ed25519pubkey(unsigned char **p, custom_ed25519_context *ed25519)
{

    for (int i = 0; i < PUBLIC_KEY_SIZE; i++)
    {
        ed25519->pub_key[i] = (*p)[i];
    }
    ed25519->len = PUBLIC_KEY_SIZE;
    /*
    printf("Stampa dopo inserimento pubblica interno\n");
    for(int i =0; i <32; i ++){
        printf("%02x",ed25519->pub_key[i]);
    }
    printf("\n");
    */
    return 0;
}

int pk_set_ed25519privkey(unsigned char **p, custom_ed25519_context *ed25519)
{

    for (int i = 0; i < PRIVATE_KEY_SIZE; i++)
    {
        ed25519->priv_key[i] = (*p)[i];
    }
    ed25519->len = PRIVATE_KEY_SIZE;
    ed25519->no_priv_key = 0;
    /*
    printf("Stampa dopo inserimento privata interno\n");
    for(int i =0; i <64; i ++){
        printf("%02x",ed25519->priv_key[i]);
    }
    printf("\n");
    */
    return 0;
}

int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, custom_ed25519_context ed25519)
{

    // int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = PUBLIC_KEY_SIZE;
    unsigned char buf[PUBLIC_KEY_SIZE];
    /*
    printf("Chiave pubblica\n");
    for(int i =0; i <32; i ++){
        printf("%02x",ed25519->pub_key[i]);
    }
    */

    for (int i = 0; i < PUBLIC_KEY_SIZE; i++)
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
        return CUSTOM_ERR_ASN1_BUF_TOO_SMALL;
    }
    *p -= len;

    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("pk_write_ed25519_pubkey - pk", buf, len);
    printf("pk_write_ed25519_pubkey - len = %d\n", len);
    #endif
    custom_memcpy(*p, buf, len);
    return (int)len;
}

int custom_ed25519_write_signature_restartable(custom_ed25519_context *ctx,
                                                custom_md_type_t md_alg,
                                                const unsigned char *hash, size_t hlen,
                                                unsigned char *sig, size_t sig_size, size_t *slen,
                                                int (*f_rng)(void *, unsigned char *, size_t),
                                                void *p_rng,
                                                custom_ed25519_restart_ctx *rs_ctx)
{

    // ed25519_sign(app_sign, hash, sizeof(hash), ctx->pub_key, ctx->priv_key);
    // int ret = CUSTOM_ERR_ERROR_CORRUPTION_DETECTED;
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
    */
    /*
    CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_raw_buffer(&p, buf,
                                                            (const unsigned char *) sign_no_tag, sizeof(sign_no_tag)));
    //CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_len(&p, buf, len));
    //CUSTOM_ASN1_CHK_ADD(len, custom_asn1_write_tag(&p, buf, CUSTOM_ASN1_BIT_STRING));
    */
    /*
    if (len > sig_size) {
        return CUSTOM_ERR_ECP_BUFFER_TOO_SMALL;
    }
    */

    // custom_memcpy(sig, p, len);
    /*
    printf("FIRMA OID\n");
    for(int i =0; i <*slen; i ++){
        printf("%02x-",sig[i]);
    }
    printf("\n");
    */
    if(ctx->no_priv_key == 0) {
        ed25519_sign(sig, hash, sizeof(hash), ctx->pub_key, ctx->priv_key);
        *slen = CUSTOM_PK_SIGNATURE_MAX_SIZE;
    } else {
        return -1;
    }
    return 0;
}

int custom_ed25519_write_signature(custom_ed25519_context *ctx,
                                    custom_md_type_t md_alg,
                                    const unsigned char *hash, size_t hlen,
                                    unsigned char *sig, size_t sig_size, size_t *slen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    return custom_ed25519_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
}

int custom_ed25519_check_pub_priv(unsigned char *priv, unsigned char *pub, unsigned char *seed)
{
    unsigned char result[PUBLIC_KEY_SIZE] = {0};
    // ed25519_create keypair(seed, priv, result);
    for (int i = 0; i < PUBLIC_KEY_SIZE; i++)
    {
        if (result[i] != pub[i])
            return 1;
    }
    return 0;
}

size_t ed25519_get_bitlen(const void *ctx)
{
    // const custom_ed25519_context *ed25519 = (const custom_ed25519_context *) ctx;
    return 8 * PUBLIC_KEY_SIZE;
}

int ed25519_can_do(custom_pk_type_t type)
{
    return type == CUSTOM_PK_ED25519;
}

int ed25519_verify_wrap(void *ctx, custom_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len)
{
    custom_ed25519_context *ed25519 = (custom_ed25519_context *)ctx;
    // ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key)
    int ret = ed25519_verify(sig, hash, hash_len, ed25519->pub_key);
    #if CUSTOM_DEBUG_PRINTS
    print_hex_string("verify pk", ed25519->pub_key, PUBLIC_KEY_SIZE);
    print_hex_string("verify hash", (unsigned char *)hash, hash_len);
    print_hex_string("verify sig", (unsigned char *)sig, sig_len);
    printf("verify returned %d\n", ret);
    #endif
    return ret==1?0:1;
    // return 0;
}

int ed25519_sign_wrap(void *ctx, custom_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t sig_size, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return custom_ed25519_write_signature((custom_ed25519_context *)ctx,
                                           md_alg, hash, hash_len,
                                           sig, sig_size, sig_len,
                                           f_rng, p_rng);
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
    if(((custom_ed25519_context *)pub)->no_priv_key == 0)  
        return custom_ed25519_check_pub_priv(((custom_ed25519_context *)pub)->priv_key,
                                            ((custom_ed25519_context *)pub)->pub_key,
                                            (unsigned char *)prv);
    return -1;
}

void *ed25519_alloc_wrap(void)
{
    void *ctx = custom_calloc(1, sizeof(custom_ed25519_context));
    if (ctx != NULL)
    {
        custom_ed25519_init((custom_ed25519_context *)ctx);
    }
    #if CUSTOM_DEBUG_PRINTS
    printf("ed25519_alloc_wrap - calloc: %lu\n", sizeof(custom_ed25519_context));
    #endif
    return ctx;
}

void ed25519_free_wrap(void *ctx)
{
    custom_ed25519_free((custom_ed25519_context *)ctx);
    custom_free(ctx);
    #if CUSTOM_DEBUG_PRINTS
    printf("ed25519_free_wrap - free: %lu\n", sizeof(custom_ed25519_context));
    #endif
}
