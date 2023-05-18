#ifndef CUSTOM_MBEDTLS_UTILS_H
#define CUSTOM_MBEDTLS_UTILS_H
#include <stddef.h>
#include "app/malloc.h"

//usr
typedef unsigned char __uint8_t;
typedef __uint8_t uint8_t;
#define INT_MAX         2147483647

//mbedtls_config.h
/**
 * \def MBEDTLS_RSA_C
 *
 * Enable the RSA public-key cryptosystem.
 *
 * Module:  library/rsa.c
 *          library/rsa_alt_helpers.c
 * Caller:  library/pk.c
 *          library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      RSA, DHE-RSA, ECDHE-RSA, RSA-PSK
 *
 * Requires: MBEDTLS_BIGNUM_C, MBEDTLS_OID_C
 */
#define MBEDTLS_RSA_C

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_BASE64_C
 *           optionally MBEDTLS_MD5_C, or PSA Crypto with MD5 (see below)
 *
 * \warning When parsing password-protected files, if MD5 is provided only by
 * a PSA driver, you must call psa_crypto_init() before the first file.
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define MBEDTLS_PEM_PARSE_C

//private_access.h
#define MBEDTLS_PRIVATE(member) member

// platform.h
#define mbedtls_free       free
#define mbedtls_calloc     calloc 

//error.h
/** This is a bug in the library */
#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        This function can be called directly however it is usually
 *        called via the #MBEDTLS_ERROR_ADD macro.
 *
 *        While a value of zero is not a negative error code, it is still an
 *        error code (that denotes success) and can be combined with both a
 *        negative error code or another value of zero.
 *
 * \note  When invasive testing is enabled via #MBEDTLS_TEST_HOOKS, also try to
 *        call \link mbedtls_test_hook_error_add \endlink.
 *
 * \param high      high-level error code. See error.h for more details.
 * \param low       low-level error code. See error.h for more details.
 * \param file      file where this error code addition occurred.
 * \param line      line where this error code addition occurred.
 */
static inline int mbedtls_error_add(int high, int low,
                                    const char *file, int line)
{
#if defined(MBEDTLS_TEST_HOOKS)
    if (*mbedtls_test_hook_error_add != NULL) {
        (*mbedtls_test_hook_error_add)(high, low, file, line);
    }
#endif
    (void) file;
    (void) line;

    return high + low;
}

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        Wrapper macro for mbedtls_error_add(). See that function for
 *        more details.
 */
#define MBEDTLS_ERROR_ADD(high, low) \
    mbedtls_error_add(high, low, __FILE__, __LINE__)

//alignment.h

/** Byte Reading Macros
 *
 * Given a multi-byte integer \p x, MBEDTLS_BYTE_n retrieves the n-th
 * byte from x, where byte 0 is the least significant byte.
 */
#define MBEDTLS_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
#define MBEDTLS_BYTE_1(x) ((uint8_t) (((x) >>  8) & 0xff))
#define MBEDTLS_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))
#define MBEDTLS_BYTE_3(x) ((uint8_t) (((x) >> 24) & 0xff))
#define MBEDTLS_BYTE_4(x) ((uint8_t) (((x) >> 32) & 0xff))
#define MBEDTLS_BYTE_5(x) ((uint8_t) (((x) >> 40) & 0xff))
#define MBEDTLS_BYTE_6(x) ((uint8_t) (((x) >> 48) & 0xff))
#define MBEDTLS_BYTE_7(x) ((uint8_t) (((x) >> 56) & 0xff))

//pk.h
/** Memory allocation failed. */
#define MBEDTLS_ERR_PK_ALLOC_FAILED        -0x3F80
/** Type mismatch, eg attempt to encrypt with an ECDSA key */
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00
/** Bad input parameters to function. */
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA      -0x3E80
/** Read/write of file failed. */
#define MBEDTLS_ERR_PK_FILE_IO_ERROR       -0x3E00
/** Unsupported key version */
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80
/** Invalid key tag or value. */
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00
/** Key algorithm is unsupported (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80
/** Private key password can't be empty. */
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00
/** Given private key password does not allow for correct decryption. */
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80
/** The pubkey tag or value is invalid (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00
/** The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80
/** Elliptic curve is unsupported (only NIST curves are supported). */
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00
/** Unavailable feature, e.g. RSA disabled for RSA key. */
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980
/** The buffer contains a valid signature followed by more data. */
#define MBEDTLS_ERR_PK_SIG_LEN_MISMATCH    -0x3900
/** The output buffer is too small. */
#define MBEDTLS_ERR_PK_BUFFER_TOO_SMALL    -0x3880

/**
 * \brief          Public key types
 */
typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
    MBEDTLS_PK_ED25519 //new_impl
} mbedtls_pk_type_t;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum {
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
} mbedtls_pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct mbedtls_pk_debug_item {
    mbedtls_pk_debug_type MBEDTLS_PRIVATE(type);
    const char *MBEDTLS_PRIVATE(name);
    void *MBEDTLS_PRIVATE(value);
} mbedtls_pk_debug_item;

/**
 * \brief           Public key information and operations
 *
 * \note        The library does not support custom pk info structures,
 *              only built-in structures returned by
 *              mbedtls_cipher_info_from_type().
 */
typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct mbedtls_pk_context {
    const mbedtls_pk_info_t *MBEDTLS_PRIVATE(pk_info);    /**< Public key information         */
    void *MBEDTLS_PRIVATE(pk_ctx);                        /**< Underlying public key context  */
} mbedtls_pk_context;

/**
 * \brief           Context for resuming operations
 */
typedef struct {
    const mbedtls_pk_info_t *MBEDTLS_PRIVATE(pk_info);    /**< Public key information         */
    void *MBEDTLS_PRIVATE(rs_ctx);                        /**< Underlying restart context     */
} mbedtls_pk_restart_ctx;

//md.h
/**
 * \brief     Supported message digests.
 *
 * \warning   MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
    MBEDTLS_MD_NONE=0,    /**< None. */
    MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512,    /**< The SHA-512 message digest. */
    MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
    MBEDTLS_MD_SHA3 //new_impl
} mbedtls_md_type_t;

#define MBEDTLS_MD_CAN_MD5

//pk_wrap.h
struct mbedtls_pk_info_t {
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)(const void *);

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)(mbedtls_pk_type_t type);

    /** Verify signature */
    int (*verify_func)(void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);

    /** Make signature */
    int (*sign_func)(void *ctx, mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng);

    /** Decrypt message */
    int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Encrypt message */
    int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Check public-private key pair */
    int (*check_pair_func)(const void *pub, const void *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng);

    /** Allocate a new context */
    void * (*ctx_alloc_func)(void);

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);

    /** Interface with the debug module */
    void (*debug_func)(const void *ctx, mbedtls_pk_debug_item *items);

};

//pem.h
/** No PEM header or footer found. */
#define MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080

//custom new_impl
#define PRIVATE_KEY_SIZE  64 // includes public key
#define PUBLIC_KEY_SIZE 32
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE 64
#define MBEDTLS_HASH_MAX_SIZE 64

typedef struct mbedtls_ed25519_context {
    int MBEDTLS_PRIVATE(ver);                    /*!<  Reserved for internal purposes.
                                                  *    Do not set this field in application
                                                  *    code. Its meaning might change without
                                                  *    notice. */
    size_t len;                 /*!<  The size of \p N in Bytes. */
    unsigned char pub_key[PUBLIC_KEY_SIZE];
    // unsigned char priv_key[PRIVATE_KEY_SIZE];

}
mbedtls_ed25519_context;

typedef void mbedtls_ed25519_restart_ctx;

#endif