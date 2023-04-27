#ifndef CUSTOM_MBEDTLS_FUNCTIONS_H
#define CUSTOM_MBEDTLS_FUNCTIONS_H
#include "custom_x509.h"

//asn1.h
/**
 * \brief       Get the tag and length of the element.
 *              Check for the requested tag.
 *              Updates the pointer to immediately behind the tag and length.
 *
 * \param p     On entry, \c *p points to the start of the ASN.1 element.
 *              On successful completion, \c *p points to the first byte
 *              after the length, i.e. the first byte of the content.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param len   On successful completion, \c *len contains the length
 *              read from the ASN.1 input.
 * \param tag   The expected tag.
 *
 * \return      0 if successful.
 * \return      #MBEDTLS_ERR_ASN1_UNEXPECTED_TAG if the data does not start
 *              with the requested tag.
 * \return      #MBEDTLS_ERR_ASN1_OUT_OF_DATA if the ASN.1 element
 *              would end beyond \p end.
 * \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the length is unparsable.
 */
int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag);

/**
 * \brief       Get the length of an ASN.1 element.
 *              Updates the pointer to immediately behind the length.
 *
 * \param p     On entry, \c *p points to the first byte of the length,
 *              i.e. immediately after the tag.
 *              On successful completion, \c *p points to the first byte
 *              after the length, i.e. the first byte of the content.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param len   On successful completion, \c *len contains the length
 *              read from the ASN.1 input.
 *
 * \return      0 if successful.
 * \return      #MBEDTLS_ERR_ASN1_OUT_OF_DATA if the ASN.1 element
 *              would end beyond \p end.
 * \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the length is unparsable.
 */
int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len);

/**
 * \brief       Free all shallow entries in a mbedtls_asn1_named_data list,
 *              but do not free internal pointer targets.
 *
 * \param name  Head of the list of named data entries to free.
 *              This function calls mbedtls_free() on each list element.
 */
void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);

/**
 * \brief          Free a heap-allocated linked list presentation of
 *                 an ASN.1 sequence, including the first element.
 *
 * There are two common ways to manage the memory used for the representation
 * of a parsed ASN.1 sequence:
 * - Allocate a head node `mbedtls_asn1_sequence *head` with mbedtls_calloc().
 *   Pass this node as the `cur` argument to mbedtls_asn1_get_sequence_of().
 *   When you have finished processing the sequence,
 *   call mbedtls_asn1_sequence_free() on `head`.
 * - Allocate a head node `mbedtls_asn1_sequence *head` in any manner,
 *   for example on the stack. Make sure that `head->next == NULL`.
 *   Pass `head` as the `cur` argument to mbedtls_asn1_get_sequence_of().
 *   When you have finished processing the sequence,
 *   call mbedtls_asn1_sequence_free() on `head->cur`,
 *   then free `head` itself in the appropriate manner.
 *
 * \param seq      The address of the first sequence component. This may
 *                 be \c NULL, in which case this functions returns
 *                 immediately.
 */
void mbedtls_asn1_sequence_free(mbedtls_asn1_sequence *seq);

/**
 * \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence.
 *              Updates the pointer to immediately behind the full
 *              AlgorithmIdentifier.
 *
 * \param p     On entry, \c *p points to the start of the ASN.1 element.
 *              On successful completion, \c *p points to the first byte
 *              beyond the AlgorithmIdentifier element.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param alg   The buffer to receive the OID.
 * \param params The buffer to receive the parameters.
 *              This is zeroized if there are no parameters.
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
int mbedtls_asn1_get_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params);

/**
 * \brief       Free all shallow entries in a mbedtls_asn1_named_data list,
 *              but do not free internal pointer targets.
 *
 * \param name  Head of the list of named data entries to free.
 *              This function calls mbedtls_free() on each list element.
 */
void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);

/**
 * \brief       Retrieve a bitstring ASN.1 tag without unused bits and its
 *              value.
 *              Updates the pointer to the beginning of the bit/octet string.
 *
 * \param p     On entry, \c *p points to the start of the ASN.1 element.
 *              On successful completion, \c *p points to the first byte
 *              of the content of the BIT STRING.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param len   On success, \c *len is the length of the content in bytes.
 *
 * \return      0 if successful.
 * \return      #MBEDTLS_ERR_ASN1_INVALID_DATA if the input starts with
 *              a valid BIT STRING with a nonzero number of unused bits.
 * \return      An ASN.1 error code if the input does not start with
 *              a valid ASN.1 BIT STRING.
 */
int mbedtls_asn1_get_bitstring_null(unsigned char **p,
                                    const unsigned char *end,
                                    size_t *len);

/**
 * \brief       Retrieve an integer ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     On entry, \c *p points to the start of the ASN.1 element.
 *              On successful completion, \c *p points to the first byte
 *              beyond the ASN.1 element.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param val   On success, the parsed value.
 *
 * \return      0 if successful.
 * \return      An ASN.1 error code if the input does not start with
 *              a valid ASN.1 INTEGER.
 * \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the parsed value does
 *              not fit in an \c int.
 */
int mbedtls_asn1_get_int(unsigned char **p,
                         const unsigned char *end,
                         int *val);

/**
 * \brief       Retrieve a boolean ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     On entry, \c *p points to the start of the ASN.1 element.
 *              On successful completion, \c *p points to the first byte
 *              beyond the ASN.1 element.
 *              On error, the value of \c *p is undefined.
 * \param end   End of data.
 * \param val   On success, the parsed value (\c 0 or \c 1).
 *
 * \return      0 if successful.
 * \return      An ASN.1 error code if the input does not start with
 *              a valid ASN.1 BOOLEAN.
 */
int mbedtls_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val);

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

/**
 * \brief           Write a boolean tag (#MBEDTLS_ASN1_BOOLEAN) and value
 *                  in ASN.1 format.
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         The reference to the current position pointer.
 * \param start     The start of the buffer, for bounds-checking.
 * \param boolean   The boolean value to write, either \c 0 or \c 1.
 *
 * \return          The number of bytes written to \p p on success.
 * \return          A negative \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start,
                            int boolean);

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

/**
 * \brief           Set the serial number for a Certificate.
 *
 * \param ctx          CRT context to use
 * \param serial       A raw array of bytes containing the serial number in big
 *                     endian format
 * \param serial_len   Length of valid bytes (expressed in bytes) in \p serial
 *                     input buffer
 *
 * \return          0 if successful, or
 *                  MBEDTLS_ERR_X509_BAD_INPUT_DATA if the provided input buffer
 *                  is too big (longer than MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN)
 */
int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len);

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. MBEDTLS_MD_SHA1)
 *
 * \param ctx       CRT context to use
 * \param md_alg    MD algorithm to use
 */
void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx, mbedtls_md_type_t md_alg);

/**
 * \brief          Parse a single DER formatted certificate and add it
 *                 to the end of the provided chained list.
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    The pointer to the start of the CRT chain to attach to.
 *                 When parsing the first CRT in a chain, this should point
 *                 to an instance of ::mbedtls_x509_crt initialized through
 *                 mbedtls_x509_crt_init().
 * \param buf      The buffer holding the DER encoded certificate.
 * \param buflen   The size in Bytes of \p buf.
 *
 * \note           This function makes an internal copy of the CRT buffer
 *                 \p buf. In particular, \p buf may be destroyed or reused
 *                 after this call returns. To avoid duplicating the CRT
 *                 buffer (at the cost of stricter lifetime constraints),
 *                 use mbedtls_x509_crt_parse_der_nocopy() instead.
 *
 * \return         \c 0 if successful.
 * \return         A negative error code on failure.
 */
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen);

/**
 * \brief          Initialize a certificate (chain)
 *
 * \param crt      Certificate chain to initialize
 */
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);

/**
 * \brief          Unallocate all certificate data
 *
 * \param crt      Certificate chain to free
 */
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);

/**
 * \brief           Generic function to add to or replace an extension in the
 *                  CRT
 *
 * \param ctx       CRT context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param critical  if the extension is critical (per the RFC's definition)
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        /*const*/ unsigned char *val, size_t val_len); //new_impl

//x509.h
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name);

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);

int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size);

int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf *serial);

int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params);

int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur);

int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_time *t);

int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig);

int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first);

int mbedtls_x509_set_extension(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val,
                               size_t val_len);

int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *ext, int tag);

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
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng); //new_impl
                                
/**
 * \brief           Free the components of a #mbedtls_pk_context.
 *
 * \param ctx       The context to clear. It must have been initialized.
 *                  If this is \c NULL, this function does nothing.
 *
 * \note            For contexts that have been set up with
 *                  mbedtls_pk_setup_opaque(), this does not free the underlying
 *                  PSA key and you still need to call psa_destroy_key()
 *                  independently if you want to destroy that key.
 */
void mbedtls_pk_free(mbedtls_pk_context *ctx);

/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        The PK context to fill. It must have been initialized
 *                  but not set up.
 *
 * \return          0 if successful, or a specific PK error code
 */
int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               mbedtls_pk_context *pk);

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
int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519);

void mbedtls_asn1_free_named_data_list_mod(int *ne); //asn1.h
int mbedtls_asn1_get_alg_mod(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf_no_arr *alg, mbedtls_asn1_buf *params); //asn1.h
int mbedtls_x509write_crt_set_issuer_name_mod(mbedtls_x509write_cert *ctx, const char *issuer_name); //x509_crt.h
int mbedtls_x509write_crt_set_subject_name_mod(mbedtls_x509write_cert *ctx, const char *subject_name); //x509_crt.h
int mbedtls_x509_string_to_names_mod(mbedtls_asn1_named_data *head, const char *name, int *ne); //x509.h
int mbedtls_x509_write_names_mod(unsigned char **p, unsigned char *start,mbedtls_asn1_named_data *arr, int ne); //x509.h
int mbedtls_x509_get_name_mod(unsigned char **p, const unsigned char *end, mbedtls_asn1_named_data *cur, int *ne); //x509.h
int mbedtls_x509_get_alg_mod(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params); //x509.h
int mbedtls_x509_get_sig_alg_mod(const mbedtls_x509_buf_crt *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts); //x509.h
int mbedtls_x509_write_extensions_mod(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *arr_exte, int ne); //x509.h
int mbedtls_asn1_store_named_data_mod( mbedtls_asn1_named_data *head,const char *oid, size_t oid_len,const unsigned char *val,size_t val_len, int *ne); //asn1write.h
int asn1_find_named_data_mod(mbedtls_asn1_named_data *list,const char *oid, size_t len, size_t ne); //asn1write.c
int x509_write_name_mod(unsigned char **p, unsigned char *start,mbedtls_asn1_named_data cur_name); //x509_create.c
int x509_write_extension_mod(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data ext); //x509_create.c
int x509_get_attr_type_value_mod(unsigned char **p,const unsigned char *end, mbedtls_asn1_named_data *cur); //x509.c

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

int x509_write_extension(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data *ext);

//x509write_crt.c
int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size);

//x509_crt.c
/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain,
                                               const unsigned char *buf,
                                               size_t buflen,
                                               int make_copy,
                                               mbedtls_x509_crt_ext_cb_t cb,
                                               void *p_ctx);

/*
 * Parse and fill a single X.509 certificate in DER format
 */
int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                                   const unsigned char *buf,
                                   size_t buflen,
                                   int make_copy,
                                   mbedtls_x509_crt_ext_cb_t cb,
                                   void *p_ctx);

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
int x509_get_version(unsigned char **p,
                            const unsigned char *end,
                            int *ver);

/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
int x509_get_dates(unsigned char **p,
                          const unsigned char *end,
                          mbedtls_x509_time *from,
                          mbedtls_x509_time *to);

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
int x509_get_uid(unsigned char **p,
                        const unsigned char *end,
                        mbedtls_x509_buf *uid, int n);

/*
 * X.509 v3 extensions
 *
 */
int x509_get_crt_ext(unsigned char **p,
                            const unsigned char *end,
                            mbedtls_x509_crt *crt,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx);

//x509.c
/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
int x509_get_attr_type_value(unsigned char **p,
                                    const unsigned char *end,
                                    mbedtls_x509_name *cur);

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
int x509_parse_time(unsigned char **p, size_t len, size_t yearlen,
                           mbedtls_x509_time *tm);

int x509_parse_int(unsigned char **p, size_t n, int *res);

int x509_date_is_valid(const mbedtls_x509_time *t);

//ans1write.c
/* This is a copy of the ASN.1 parsing function mbedtls_asn1_find_named_data(),
 * which is replicated to avoid a dependency ASN1_WRITE_C on ASN1_PARSE_C. */
mbedtls_asn1_named_data *asn1_find_named_data(mbedtls_asn1_named_data *list, const char *oid, size_t len);

static int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag);

//asn1parse.c
int asn1_get_tagged_int(unsigned char **p,
                               const unsigned char *end,
                               int tag, int *val);

//pkparse.c
/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params);
#endif