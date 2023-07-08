#ifndef CUSTOM_UTILS_H
#define CUSTOM_UTILS_H
#include <stddef.h>
#include "app/malloc.h"

//usr
typedef unsigned char __uint8_t;
typedef unsigned int __uint32_t;
typedef __uint8_t uint8_t;
typedef __uint32_t uint32_t;
#define INT_MAX         2147483647

//custom_config.h

/**
 * \def CUSTOM_HAVE_TIME_DATE
 *
 * System has time.h, time(), and an implementation for
 * custom_platform_gmtime_r() (see below).
 * The time needs to be correct (not necessarily very accurate, but at least
 * the date should be correct). This is used to verify the validity period of
 * X.509 certificates.
 *
 * Comment if your system does not have a correct clock.
 *
 * \note custom_platform_gmtime_r() is an abstraction in platform_util.h that
 * behaves similarly to the gmtime_r() function from the C standard. Refer to
 * the documentation for custom_platform_gmtime_r() for more information.
 *
 * \note It is possible to configure an implementation for
 * custom_platform_gmtime_r() at compile-time by using the macro
 * CUSTOM_PLATFORM_GMTIME_R_ALT.
 */
// #define CUSTOM_HAVE_TIME_DATE

/**
 * \def CUSTOM_RSA_C
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
 * Requires: CUSTOM_BIGNUM_C, CUSTOM_OID_C
 */
#define CUSTOM_RSA_C

/**
 * \def CUSTOM_PEM_PARSE_C
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
 * Requires: CUSTOM_BASE64_C
 *           optionally CUSTOM_MD5_C, or PSA Crypto with MD5 (see below)
 *
 * \warning When parsing password-protected files, if MD5 is provided only by
 * a PSA driver, you must call psa_crypto_init() before the first file.
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define CUSTOM_PEM_PARSE_C

//private_access.h
#define CUSTOM_PRIVATE(member) member

// platform.h
#define custom_free       free
#define custom_calloc     calloc 

// platform_util.h

#if defined(CUSTOM_HAVE_TIME_DATE)
/**
 * \brief      Platform-specific implementation of gmtime_r()
 *
 *             The function is a thread-safe abstraction that behaves
 *             similarly to the gmtime_r() function from Unix/POSIX.
 *
 *             Mbed TLS will try to identify the underlying platform and
 *             make use of an appropriate underlying implementation (e.g.
 *             gmtime_r() for POSIX and gmtime_s() for Windows). If this is
 *             not possible, then gmtime() will be used. In this case, calls
 *             from the library to gmtime() will be guarded by the mutex
 *             custom_threading_gmtime_mutex if CUSTOM_THREADING_C is
 *             enabled. It is recommended that calls from outside the library
 *             are also guarded by this mutex.
 *
 *             If CUSTOM_PLATFORM_GMTIME_R_ALT is defined, then Mbed TLS will
 *             unconditionally use the alternative implementation for
 *             custom_platform_gmtime_r() supplied by the user at compile time.
 *
 * \param tt     Pointer to an object containing time (in seconds) since the
 *               epoch to be converted
 * \param tm_buf Pointer to an object where the results will be stored
 *
 * \return      Pointer to an object of type struct tm on success, otherwise
 *              NULL
 */
struct tm *custom_platform_gmtime_r(const custom_time_t *tt,
                                     struct tm *tm_buf);
#endif /* CUSTOM_HAVE_TIME_DATE */

// platform_time.h

#if defined(CUSTOM_HAVE_TIME_DATE)

#include <time.h>
typedef time_t custom_time_t;

#define custom_time   time

#endif /* CUSTOM_HAVE_TIME_DATE */

//error.h
/** This is a bug in the library */
#define CUSTOM_ERR_ERROR_CORRUPTION_DETECTED -0x006E

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        This function can be called directly however it is usually
 *        called via the #CUSTOM_ERROR_ADD macro.
 *
 *        While a value of zero is not a negative error code, it is still an
 *        error code (that denotes success) and can be combined with both a
 *        negative error code or another value of zero.
 *
 * \note  When invasive testing is enabled via #CUSTOM_TEST_HOOKS, also try to
 *        call \link custom_test_hook_error_add \endlink.
 *
 * \param high      high-level error code. See error.h for more details.
 * \param low       low-level error code. See error.h for more details.
 * \param file      file where this error code addition occurred.
 * \param line      line where this error code addition occurred.
 */
static inline int custom_error_add(int high, int low,
                                    const char *file, int line)
{
#if defined(CUSTOM_TEST_HOOKS)
    if (*custom_test_hook_error_add != NULL) {
        (*custom_test_hook_error_add)(high, low, file, line);
    }
#endif
    (void) file;
    (void) line;

    return high + low;
}

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        Wrapper macro for custom_error_add(). See that function for
 *        more details.
 */
#define CUSTOM_ERROR_ADD(high, low) \
    custom_error_add(high, low, __FILE__, __LINE__)

//alignment.h

/** Byte Reading Macros
 *
 * Given a multi-byte integer \p x, CUSTOM_BYTE_n retrieves the n-th
 * byte from x, where byte 0 is the least significant byte.
 */
#define CUSTOM_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
#define CUSTOM_BYTE_1(x) ((uint8_t) (((x) >>  8) & 0xff))
#define CUSTOM_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))
#define CUSTOM_BYTE_3(x) ((uint8_t) (((x) >> 24) & 0xff))
#define CUSTOM_BYTE_4(x) ((uint8_t) (((x) >> 32) & 0xff))
#define CUSTOM_BYTE_5(x) ((uint8_t) (((x) >> 40) & 0xff))
#define CUSTOM_BYTE_6(x) ((uint8_t) (((x) >> 48) & 0xff))
#define CUSTOM_BYTE_7(x) ((uint8_t) (((x) >> 56) & 0xff))

//pk.h
/** Memory allocation failed. */
#define CUSTOM_ERR_PK_ALLOC_FAILED        -0x3F80
/** Type mismatch, eg attempt to encrypt with an ECDSA key */
#define CUSTOM_ERR_PK_TYPE_MISMATCH       -0x3F00
/** Bad input parameters to function. */
#define CUSTOM_ERR_PK_BAD_INPUT_DATA      -0x3E80
/** Read/write of file failed. */
#define CUSTOM_ERR_PK_FILE_IO_ERROR       -0x3E00
/** Unsupported key version */
#define CUSTOM_ERR_PK_KEY_INVALID_VERSION -0x3D80
/** Invalid key tag or value. */
#define CUSTOM_ERR_PK_KEY_INVALID_FORMAT  -0x3D00
/** Key algorithm is unsupported (only RSA and EC are supported). */
#define CUSTOM_ERR_PK_UNKNOWN_PK_ALG      -0x3C80
/** Private key password can't be empty. */
#define CUSTOM_ERR_PK_PASSWORD_REQUIRED   -0x3C00
/** Given private key password does not allow for correct decryption. */
#define CUSTOM_ERR_PK_PASSWORD_MISMATCH   -0x3B80
/** The pubkey tag or value is invalid (only RSA and EC are supported). */
#define CUSTOM_ERR_PK_INVALID_PUBKEY      -0x3B00
/** The algorithm tag or value is invalid. */
#define CUSTOM_ERR_PK_INVALID_ALG         -0x3A80
/** Elliptic curve is unsupported (only NIST curves are supported). */
#define CUSTOM_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00
/** Unavailable feature, e.g. RSA disabled for RSA key. */
#define CUSTOM_ERR_PK_FEATURE_UNAVAILABLE -0x3980
/** The buffer contains a valid signature followed by more data. */
#define CUSTOM_ERR_PK_SIG_LEN_MISMATCH    -0x3900
/** The output buffer is too small. */
#define CUSTOM_ERR_PK_BUFFER_TOO_SMALL    -0x3880

/**
 * \brief          Public key types
 */
typedef enum {
    CUSTOM_PK_NONE=0,
    CUSTOM_PK_RSA,
    CUSTOM_PK_ECKEY,
    CUSTOM_PK_ECKEY_DH,
    CUSTOM_PK_ECDSA,
    CUSTOM_PK_RSA_ALT,
    CUSTOM_PK_RSASSA_PSS,
    CUSTOM_PK_OPAQUE,
    CUSTOM_PK_ED25519 //new_impl
} custom_pk_type_t;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum {
    CUSTOM_PK_DEBUG_NONE = 0,
    CUSTOM_PK_DEBUG_MPI,
    CUSTOM_PK_DEBUG_ECP,
} custom_pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct custom_pk_debug_item {
    custom_pk_debug_type CUSTOM_PRIVATE(type);
    const char *CUSTOM_PRIVATE(name);
    void *CUSTOM_PRIVATE(value);
} custom_pk_debug_item;

/**
 * \brief           Public key information and operations
 *
 * \note        The library does not support custom pk info structures,
 *              only built-in structures returned by
 *              custom_cipher_info_from_type().
 */
typedef struct custom_pk_info_t custom_pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct custom_pk_context {
    const custom_pk_info_t *CUSTOM_PRIVATE(pk_info);    /**< Public key information         */
    void *CUSTOM_PRIVATE(pk_ctx);                        /**< Underlying public key context  */
} custom_pk_context;

/**
 * \brief           Context for resuming operations
 */
typedef struct {
    const custom_pk_info_t *CUSTOM_PRIVATE(pk_info);    /**< Public key information         */
    void *CUSTOM_PRIVATE(rs_ctx);                        /**< Underlying restart context     */
} custom_pk_restart_ctx;

//md.h

/** The selected feature is not available. */
#define CUSTOM_ERR_MD_FEATURE_UNAVAILABLE                -0x5080
/** Bad input parameters to function. */
#define CUSTOM_ERR_MD_BAD_INPUT_DATA                     -0x5100
/** Failed to allocate memory. */
#define CUSTOM_ERR_MD_ALLOC_FAILED                       -0x5180
/** Opening or reading of file failed. */
#define CUSTOM_ERR_MD_FILE_IO_ERROR                      -0x5200

/**
 * \brief     Supported message digests.
 *
 * \warning   MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
    CUSTOM_MD_NONE=0,    /**< None. */
    CUSTOM_MD_MD5,       /**< The MD5 message digest. */
    CUSTOM_MD_SHA1,      /**< The SHA-1 message digest. */
    CUSTOM_MD_SHA224,    /**< The SHA-224 message digest. */
    CUSTOM_MD_SHA256,    /**< The SHA-256 message digest. */
    CUSTOM_MD_SHA384,    /**< The SHA-384 message digest. */
    CUSTOM_MD_SHA512,    /**< The SHA-512 message digest. */
    CUSTOM_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
    CUSTOM_MD_KEYSTONE_SHA3 //new_impl
} custom_md_type_t;

/**
 * Opaque struct.
 *
 * Constructed using either #custom_md_info_from_string or
 * #custom_md_info_from_type.
 *
 * Fields can be accessed with #custom_md_get_size,
 * #custom_md_get_type and #custom_md_get_name.
 */
/* Defined internally in library/md_wrap.h. */
typedef struct custom_md_info_t custom_md_info_t;

#define CUSTOM_MD_CAN_MD5

//pk_wrap.h
struct custom_pk_info_t {
    /** Public key type */
    custom_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)(const void *);

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)(custom_pk_type_t type);

    /** Verify signature */
    int (*verify_func)(void *ctx, custom_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);

    /** Make signature */
    int (*sign_func)(void *ctx, custom_md_type_t md_alg,
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
    void (*debug_func)(const void *ctx, custom_pk_debug_item *items);

};

// md_wrap.h
/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct custom_md_info_t {
    /** Name of the message digest */
    const char *name;

    /** Digest identifier */
    custom_md_type_t type;

    /** Output length of the digest function in bytes */
    unsigned char size;

    /** Block length of the digest function in bytes */
    unsigned char block_size;
};

//pem.h
/** No PEM header or footer found. */
#define CUSTOM_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080

//custom new_impl
#define PRIVATE_KEY_SIZE  64 // includes public key
#define PUBLIC_KEY_SIZE 32
#define CUSTOM_PK_SIGNATURE_MAX_SIZE 64
#define CUSTOM_HASH_MAX_SIZE 64

typedef struct custom_ed25519_context {
    int CUSTOM_PRIVATE(ver);                    /*!<  Reserved for internal purposes.
                                                  *    Do not set this field in application
                                                  *    code. Its meaning might change without
                                                  *    notice. */
    size_t len;                 /*!<  The size of \p N in Bytes. */
    unsigned char pub_key[PUBLIC_KEY_SIZE];
    unsigned char priv_key[PRIVATE_KEY_SIZE];
    int no_priv_key;

}
custom_ed25519_context;

typedef void custom_ed25519_restart_ctx;

#endif