#ifndef CUSTOM_MBEDTLS_FUNCTIONS_H
#define CUSTOM_MBEDTLS_FUNCTIONS_H
#include "x509.h"

//asn1.h

//asn1write.h
/**
 * \brief           Create or find a specific named_data entry for writing in a
 *                  sequence or list based on the OID. If not already in there,
 *                  a new entry is added to the head of the list.
 *                  Warning: Destructive behaviour for the val data!
 *
 * \param list      The pointer to the location of the head of the list to seek
 *                  through (will be updated in case of a new entry).
 * \param oid       The OID to look for.
 * \param oid_len   The size of the OID.
 * \param val       The associated data to store. If this is \c NULL,
 *                  no data is copied to the new or existing buffer.
 * \param val_len   The minimum length of the data buffer needed.
 *                  If this is 0, do not allocate a buffer for the associated
 *                  data.
 *                  If the OID was already present, enlarge, shrink or free
 *                  the existing buffer to fit \p val_len.
 *
 * \return          A pointer to the new / existing entry on success.
 * \return          \c NULL if there was a memory allocation error.
 */
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(mbedtls_asn1_named_data **list,
                                                       const char *oid, size_t oid_len,
                                                       const unsigned char *val,
                                                       size_t val_len);

/**
 * \brief           Write a length field in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param len       The length value to write.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start,
                           size_t len);

/**
 * \brief           Write an ASN.1 tag in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param tag       The tag to write.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start,
                           unsigned char tag);

/**
 * \brief           Write an AlgorithmIdentifier sequence in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param oid       The OID of the algorithm to write.
 * \param oid_len   The length of the algorithm's OID.
 * \param par_len   The length of the parameters, which must be already written.
 *                  If 0, NULL parameters are added
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_algorithm_identifier(unsigned char **p,
                                            const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len);

/**
 * \brief           Write a NULL tag (#MBEDTLS_ASN1_NULL) with zero data
 *                  in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start);

/**
 * \brief           Write an OID tag (#MBEDTLS_ASN1_OID) and data
 *                  in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param oid       The OID to write.
 * \param oid_len   The length of the OID.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len);

/**
 * \brief           Write raw buffer data.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param buf       The data buffer to write.
 * \param size      The length of the data buffer.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size);

/**
 * \brief           Write a string in ASN.1 format using a specific
 *                  string encoding tag.

 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param tag       The string encoding tag to write, e.g.
 *                  #MBEDTLS_ASN1_UTF8_STRING.
 * \param text      The string to write.
 * \param text_len  The length of \p text in bytes (which might
 *                  be strictly larger than the number of characters).
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative error code on failure.
 */
int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start,
                                     int tag, const char *text,
                                     size_t text_len);

/**
 * \brief           Write an int tag (#MBEDTLS_ASN1_INTEGER) and value
 *                  in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param val       The integer value to write.
 *                  It must be non-negative.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val);

//oid.h
/**
 * \brief          Translate md_type and pk_type into SignatureAlgorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param pk_alg   public key algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_oid_by_sig_alg(mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                                   const char **oid, size_t *olen);

//x509_crt.h
/**
 * \brief           Initialize a CRT writing context
 *
 * \param ctx       CRT context to initialize
 */
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx);

/**
 * \brief           Set the subject public key for the certificate
 *
 * \param ctx       CRT context to use
 * \param key       public key to include
 */
void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);

/**
 * \brief           Set the validity period for a Certificate
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CRT context to use
 * \param not_before    not_before timestamp
 * \param not_after     not_after timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx, const char *not_before,
                                       const char *not_after);

/**
 * \brief           Set the issuer key used for signing the certificate
 *
 * \param ctx       CRT context to use
 * \param key       private key to sign with
 */
void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);

/**
 * \brief           Write a built up certificate to a X509 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       certificate to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function. This must not be \c NULL.
 * \param p_rng     RNG parameter
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 *
 * \note            \p f_rng is used for the signature operation.
 */
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);

//x509.h
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name);

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);

//pk.h
/** \ingroup pk_module */
/**
 * \brief           Parse a public key in PEM or DER format
 *
 * \note            If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                  subsystem must have been initialized by calling
 *                  psa_crypto_init() before calling this function.
 *
 * \param ctx       The PK context to fill. It must have been initialized
 *                  but not set up.
 * \param key       Input buffer to parse.
 *                  The buffer must contain the input exactly, with no
 *                  extra trailing material. For PEM, the buffer must
 *                  contain a null-terminated string.
 * \param keylen    Size of \b key in bytes.
 *                  For PEM data, this includes the terminating null byte,
 *                  so \p keylen must be equal to `strlen(key) + 1`.
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            For compressed points, see #MBEDTLS_ECP_PF_COMPRESSED for
 *                  limitations.
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen, int type_k); //new_impl

/**
 * \brief           Return information associated with the given PK type
 *
 * \param pk_type   PK type to search for.
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);

/**
 * \brief           Initialize a #mbedtls_pk_context (as NONE).
 *
 * \param ctx       The context to initialize.
 *                  This must not be \c NULL.
 */
void mbedtls_pk_init(mbedtls_pk_context *ctx);

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. It must not have been set
 *                  up yet (type #MBEDTLS_PK_NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  MBEDTLS_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  MBEDTLS_ERR_PK_ALLOC_FAILED on allocation failure.
 *
 * \note            For contexts holding an RSA-alt key, use
 *                  \c mbedtls_pk_setup_rsa_alt() instead.
 */
int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);

/**
 * \brief           Get the key type
 *
 * \param ctx       The PK context to use. It must have been initialized.
 *
 * \return          Type on success.
 * \return          #MBEDTLS_PK_NONE for a context that has not been set up.
 */
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx);

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       PK context which must contain a valid public or private key.
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);

/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       PK context which must contain a valid public or private key.
 *
 * \return          the length written or a negative error code
 */
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const mbedtls_pk_context *key);

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 * \param f_rng     RNG function, must not be \c NULL.
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDTLS_MD_NONE.
 */
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/**
 * \brief           Restartable version of \c mbedtls_pk_sign()
 *
 * \note            Performs the same job as \c mbedtls_pk_sign(), but can
 *                  return early and restart according to the limit set with
 *                  \c mbedtls_ecp_set_max_ops() to reduce blocking for ECC
 *                  operations. For RSA, same as \c mbedtls_pk_sign().
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes for mbedtls_pk_sign())
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 * \param f_rng     RNG function, must not be \c NULL.
 * \param p_rng     RNG parameter
 * \param rs_ctx    Restart context (NULL to disable restart)
 *
 * \return          See \c mbedtls_pk_sign().
 * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c mbedtls_ecp_set_max_ops().
 */
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx);
                                
//custom new_impl
size_t ed25519_get_bitlen(const void *ctx);
int ed25519_can_do(mbedtls_pk_type_t type);
void/* mbedtls_ed25519_context*/ ed25519_alloc_wrap(void);
void ed25519_free_wrap(void *ctx);
int mbedtls_ed25519_check_pub_priv(unsigned char* priv, unsigned char* pub, unsigned char* seed);
int ed25519_check_pair_wrap(const void *pub, const void *prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_encrypt_wrap(void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_decrypt_wrap(void *ctx, 
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize, 
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int ed25519_sign_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,unsigned char *sig,
                        size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_verify_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, 
                          const unsigned char *sig, size_t sig_len);
void mbedtls_ed25519_free(mbedtls_ed25519_context *ctx);
void mbedtls_ed25519_init(mbedtls_ed25519_context *ctx);
int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context ed25519);  

//x509_create.c
const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len);

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
int x509_write_name(unsigned char **p, unsigned char *start, mbedtls_asn1_named_data *cur_name);

//x509write_crt.c
int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size);

//ans1write.c
/* This is a copy of the ASN.1 parsing function mbedtls_asn1_find_named_data(),
 * which is replicated to avoid a dependency ASN1_WRITE_C on ASN1_PARSE_C. */
mbedtls_asn1_named_data *asn1_find_named_data(mbedtls_asn1_named_data *list, const char *oid, size_t len);

static int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag);

#endif