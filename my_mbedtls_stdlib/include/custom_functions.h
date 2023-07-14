#ifndef CUSTOM_FUNCTIONS_H
#define CUSTOM_FUNCTIONS_H
#include "custom_x509.h"
#include "custom_string.h"
#include "app/syscall.h"
#include <stdio.h>
#define CUSTOM_DEBUG_PRINTS 0

// asn1.h
int custom_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len);
int custom_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag);
int custom_asn1_get_bool(unsigned char **p, const unsigned char *end, int *val);
int custom_asn1_get_int(unsigned char **p, const unsigned char *end, int *val);
int custom_asn1_get_bitstring(unsigned char **p, const unsigned char *end, custom_asn1_bitstring *bs);
int custom_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end, size_t *len);
void custom_asn1_sequence_free(custom_asn1_sequence *seq); 
int custom_asn1_get_alg(unsigned char **p, const unsigned char *end, custom_asn1_buf *alg, custom_asn1_buf *params);
void custom_asn1_free_named_data_list(custom_asn1_named_data **head);
void custom_asn1_free_named_data_list_shallow(custom_asn1_named_data *name);

// asn1write.h
int custom_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len);
int custom_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag);
int custom_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start, const unsigned char *buf, size_t size);
int custom_asn1_write_null(unsigned char **p, const unsigned char *start);
int custom_asn1_write_oid(unsigned char **p, const unsigned char *start, const char *oid, size_t oid_len);
int custom_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start, const char *oid, size_t oid_len, size_t par_len);
int custom_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean);
int custom_asn1_write_int(unsigned char **p, const unsigned char *start, int val);
int custom_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag, const char *text, size_t text_len);
int custom_asn1_write_bitstring(unsigned char **p, const unsigned char *start, const unsigned char *buf, size_t bits);
int custom_asn1_write_named_bitstring(unsigned char **p, const unsigned char *start, const unsigned char *buf, size_t bits);
custom_asn1_named_data *custom_asn1_store_named_data(custom_asn1_named_data **head, const char *oid, size_t oid_len, const unsigned char *val, size_t val_len);

// md.h
const custom_md_info_t *custom_md_info_from_type(custom_md_type_t md_type);
int custom_md(const custom_md_info_t *md_info, const unsigned char *input, size_t ilen, unsigned char *output);
unsigned char custom_md_get_size(const custom_md_info_t *md_info);

// pk.h
void custom_pk_init(custom_pk_context *ctx);
void custom_pk_free(custom_pk_context *ctx);
const custom_pk_info_t *custom_pk_info_from_type(custom_pk_type_t pk_type);
int custom_pk_setup(custom_pk_context *ctx, const custom_pk_info_t *info);
int custom_pk_can_do(const custom_pk_context *ctx, custom_pk_type_t type);
int custom_pk_verify_restartable(custom_pk_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len, custom_pk_restart_ctx *rs_ctx);
int custom_pk_verify(custom_pk_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int custom_pk_verify_ext(custom_pk_type_t type, const void *options, custom_pk_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int custom_pk_sign_restartable(custom_pk_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, custom_pk_restart_ctx *rs_ctx);
int custom_pk_sign(custom_pk_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
size_t custom_pk_get_bitlen(const custom_pk_context *ctx);
custom_pk_type_t custom_pk_get_type(const custom_pk_context *ctx);

int custom_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, custom_pk_context *pk);
int custom_pk_parse_public_key(custom_pk_context *ctx, const unsigned char *key, size_t keylen, int type_k);

int custom_pk_write_pubkey(unsigned char **p, unsigned char *start, const custom_pk_context *key);
int custom_pk_write_pubkey_der(const custom_pk_context *key, unsigned char *buf, size_t size);

// custom new_impl
custom_ed25519_context *custom_pk_ed25519(const custom_pk_context pk);
void custom_ed25519_init(custom_ed25519_context *ctx);
void custom_ed25519_free(custom_ed25519_context *ctx);
int pk_set_ed25519pubkey(unsigned char **p, custom_ed25519_context *ed25519);
int pk_set_ed25519privkey(unsigned char **p, custom_ed25519_context *ed25519);
int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, custom_ed25519_context ed25519);
int custom_ed25519_write_signature_restartable(custom_ed25519_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t sig_size, size_t *slen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, custom_ed25519_restart_ctx *rs_ctx);
int custom_ed25519_write_signature(custom_ed25519_context *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hlen, unsigned char *sig, size_t sig_size, size_t *slen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int custom_ed25519_check_pub_priv(unsigned char *priv, unsigned char *pub, unsigned char *seed);
size_t ed25519_get_bitlen(const void *ctx);
int ed25519_can_do(custom_pk_type_t type);
int ed25519_verify_wrap(void *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int ed25519_sign_wrap(void *ctx, custom_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_decrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_encrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_check_pair_wrap(const void *pub, const void *prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
void *ed25519_alloc_wrap(void);
void ed25519_free_wrap(void *ctx);

int  checkTCIValue(const custom_x509_name *id, const custom_x509_buf *tci);
int getAttestationPublicKey(custom_x509_csr *csr, unsigned char *pk);
int getReferenceTCI(custom_x509_csr *csr, unsigned char *tci);
int checkEnclaveTCI(unsigned char *tci, int tci_len);

int custom_x509write_csr_set_nonce(custom_x509write_csr *ctx, unsigned char *nonce);
int custom_x509write_csr_set_attestation_proof(custom_x509write_csr *ctx, unsigned char *attest_proof);
int custom_x509write_csr_set_dice_certs(custom_x509write_csr *ctx, unsigned char *certs[], int *sizes);

void custom_platform_zeroize(void *buf, size_t len);

// x509.h
int custom_x509_get_serial(unsigned char **p, const unsigned char *end, custom_x509_buf *serial);
int custom_x509_get_alg(unsigned char **p, const unsigned char *end, custom_x509_buf *alg, custom_x509_buf *params);
int custom_x509_get_name(unsigned char **p, const unsigned char *end, custom_x509_name *cur);
int custom_x509_get_time(unsigned char **p, const unsigned char *end, custom_x509_time *tm);
int custom_x509_get_sig(unsigned char **p, const unsigned char *end, custom_x509_buf *sig);
int custom_x509_get_sig_alg(const custom_x509_buf *sig_oid, const custom_x509_buf *sig_params, custom_md_type_t *md_alg, custom_pk_type_t *pk_alg, void **sig_opts);
int custom_x509_get_ext(unsigned char **p, const unsigned char *end, custom_x509_buf *ext, int tag);
int custom_x509_time_is_past(const custom_x509_time *to);
int custom_x509_time_is_future(const custom_x509_time *from);
int custom_x509_get_subject_alt_name(unsigned char **p, const unsigned char *end, custom_x509_sequence *subject_alt_name);
int custom_x509_get_ns_cert_type(unsigned char **p, const unsigned char *end, unsigned char *ns_cert_type);
int custom_x509_get_key_usage(unsigned char **p, const unsigned char *end, unsigned int *key_usage);
int custom_x509_parse_subject_alt_name(const custom_x509_buf *san_buf, custom_x509_subject_alternative_name *san); 
void custom_x509_free_subject_alt_name(custom_x509_subject_alternative_name *san);

int custom_x509_string_to_names(custom_asn1_named_data **head, const char *name);
int custom_x509_set_extension(custom_asn1_named_data **head, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len);
int custom_x509_write_names(unsigned char **p, unsigned char *start, custom_asn1_named_data *first);
int custom_x509_write_sig(unsigned char **p, unsigned char *start, const char *oid, size_t oid_len, unsigned char *sig, size_t size);
int custom_x509_write_extensions(unsigned char **p, unsigned char *start, custom_asn1_named_data *first);

// x509_crt.h
int custom_x509_crt_parse_der(custom_x509_crt *chain, const unsigned char *buf, size_t buflen);
int custom_x509_crt_check_key_usage(const custom_x509_crt *crt, unsigned int usage);
int custom_x509_crt_verify(custom_x509_crt *crt, custom_x509_crt *trust_ca, custom_x509_crl *ca_crl, const char *cn, uint32_t *flags, int (*f_vrfy)(void *, custom_x509_crt *, int, uint32_t *), void *p_vrfy);
void custom_x509_crt_init(custom_x509_crt *crt);
void custom_x509_crt_free(custom_x509_crt *crt);

void custom_x509write_crt_init(custom_x509write_cert *ctx);
void custom_x509write_crt_free(custom_x509write_cert *ctx);
void custom_x509write_crt_set_md_alg(custom_x509write_cert *ctx, custom_md_type_t md_alg);
void custom_x509write_crt_set_subject_key(custom_x509write_cert *ctx, custom_pk_context *key);
void custom_x509write_crt_set_issuer_key(custom_x509write_cert *ctx, custom_pk_context *key);
int custom_x509write_crt_set_subject_name(custom_x509write_cert *ctx, const char *subject_name);
int custom_x509write_crt_set_issuer_name(custom_x509write_cert *ctx, const char *issuer_name);
int custom_x509write_crt_set_serial_raw(custom_x509write_cert *ctx, unsigned char *serial, size_t serial_len);
int custom_x509write_crt_set_validity(custom_x509write_cert *ctx, const char *not_before, const char *not_after);
int custom_x509write_crt_set_extension(custom_x509write_cert *ctx, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len);
int custom_x509write_crt_set_basic_constraints(custom_x509write_cert *ctx, int is_ca, int max_pathlen);
int custom_x509write_crt_der(custom_x509write_cert *ctx, unsigned char *buf, size_t size, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

// x509_csr.h
int custom_x509_csr_parse_der(custom_x509_csr *csr, const unsigned char *buf, size_t buflen);
void custom_x509_csr_init(custom_x509_csr *csr);
void custom_x509_csr_free(custom_x509_csr *csr);

void custom_x509write_csr_init(custom_x509write_csr *ctx);
void custom_x509write_csr_free(custom_x509write_csr *ctx);
void custom_x509write_csr_set_md_alg(custom_x509write_csr *ctx, custom_md_type_t md_alg);
void custom_x509write_csr_set_key(custom_x509write_csr *ctx, custom_pk_context *key);
int custom_x509write_csr_set_subject_name(custom_x509write_csr *ctx, const char *subject_name);
int custom_x509write_csr_set_extension(custom_x509write_csr *ctx, const char *oid, size_t oid_len, int critical, const unsigned char *val, size_t val_len);
int custom_x509write_csr_set_subject_alternative_name(custom_x509write_csr *ctx, const custom_x509_san_list *san_list);
int custom_x509write_csr_set_key_usage(custom_x509write_csr *ctx, unsigned char key_usage);
int custom_x509write_csr_set_ns_cert_type(custom_x509write_csr *ctx, unsigned char ns_cert_type);
int custom_x509write_csr_der(custom_x509write_csr *ctx, unsigned char *buf, size_t size, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

#endif