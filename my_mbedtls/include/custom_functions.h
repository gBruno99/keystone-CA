#ifndef CUSTOM_MBEDTLS_FUNCTIONS_H
#define CUSTOM_MBEDTLS_FUNCTIONS_H
#include "custom_x509.h"
#include "custom_string.h"
#include "printf.h"
#define MBEDTLS_DEBUG_PRINTS 1

// asn1.h
int mbedtls_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len);
int mbedtls_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag);
int mbedtls_asn1_get_bool(unsigned char **p, const unsigned char *end, int *val);
int mbedtls_asn1_get_int(unsigned char **p, const unsigned char *end, int *val);
int mbedtls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end, size_t *len);
void mbedtls_asn1_sequence_free(mbedtls_asn1_sequence *seq); 
int mbedtls_asn1_get_alg(unsigned char **p, const unsigned char *end, mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params);
void mbedtls_asn1_free_named_data_list(mbedtls_asn1_named_data **head);
void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);

// asn1write.h
int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len);
int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag);
int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start, const unsigned char *buf, size_t size);
int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start);
int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start, const char *oid, size_t oid_len);
int mbedtls_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start, const char *oid, size_t oid_len, size_t par_len);
int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean);
int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val);
int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag, const char *text, size_t text_len);
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len, const unsigned char *val, size_t val_len);

// pk.h
void mbedtls_pk_init(mbedtls_pk_context *ctx);
void mbedtls_pk_free(mbedtls_pk_context *ctx);
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);
int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, mbedtls_pk_restart_ctx *rs_ctx);
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx);

int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, mbedtls_pk_context *pk);
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, int type_k);

int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start, const mbedtls_pk_context *key);
int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size);

// custom new_impl
mbedtls_ed25519_context *mbedtls_pk_ed25519(const mbedtls_pk_context pk);
void mbedtls_ed25519_init(mbedtls_ed25519_context *ctx);
void mbedtls_ed25519_free(mbedtls_ed25519_context *ctx);
int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context ed25519);
int mbedtls_ed25519_write_signature_restartable(mbedtls_ed25519_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t sig_size, size_t *slen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, mbedtls_ed25519_restart_ctx *rs_ctx);
int mbedtls_ed25519_write_signature(mbedtls_ed25519_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t sig_size, size_t *slen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_ed25519_check_pub_priv(unsigned char *priv, unsigned char *pub, unsigned char *seed);
size_t ed25519_get_bitlen(const void *ctx);
int ed25519_can_do(mbedtls_pk_type_t type);
int ed25519_verify_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int ed25519_sign_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_decrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_encrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_check_pair_wrap(const void *pub, const void *prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
void *ed25519_alloc_wrap(void);
void ed25519_free_wrap(void *ctx);

// x509.h
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *serial);
int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *alg, mbedtls_x509_buf *params);
int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end, mbedtls_x509_name *cur);
int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end, mbedtls_x509_time *tm);
int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig);
int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params, mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg, void **sig_opts);
int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *ext, int tag);

int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name);
int mbedtls_x509_set_extension(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len);
int mbedtls_x509_write_names(unsigned char **p, unsigned char *start, mbedtls_asn1_named_data *first);
int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start, const char *oid, size_t oid_len, unsigned char *sig, size_t size);
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start, mbedtls_asn1_named_data *first);

// x509_crt.h
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen);
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);

void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx);
void mbedtls_x509write_crt_free(mbedtls_x509write_cert *ctx);
void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx, mbedtls_md_type_t md_alg);
void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx, const char *subject_name);
int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx, const char *issuer_name);
int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx, unsigned char *serial, size_t serial_len);
int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx, const char *not_before, const char *not_after);
int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len);
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

#endif