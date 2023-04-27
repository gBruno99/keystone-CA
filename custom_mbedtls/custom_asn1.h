#ifndef CUSTOM_MBEDTLS_ASN1_H
#define CUSTOM_MBEDTLS_ASN1_H
#include <stddef.h>
//asn1.h

/**
 * \name DER constants
 * These constants comply with the DER encoded ASN.1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::mbedtls_x509_buf.
 * \{
 */
#define MBEDTLS_ASN1_BOOLEAN                 0x01
#define MBEDTLS_ASN1_INTEGER                 0x02
#define MBEDTLS_ASN1_BIT_STRING              0x03
#define MBEDTLS_ASN1_OCTET_STRING            0x04
#define MBEDTLS_ASN1_NULL                    0x05
#define MBEDTLS_ASN1_OID                     0x06
#define MBEDTLS_ASN1_ENUMERATED              0x0A
#define MBEDTLS_ASN1_UTF8_STRING             0x0C
#define MBEDTLS_ASN1_SEQUENCE                0x10
#define MBEDTLS_ASN1_SET                     0x11
#define MBEDTLS_ASN1_PRINTABLE_STRING        0x13
#define MBEDTLS_ASN1_T61_STRING              0x14
#define MBEDTLS_ASN1_IA5_STRING              0x16
#define MBEDTLS_ASN1_UTC_TIME                0x17
#define MBEDTLS_ASN1_GENERALIZED_TIME        0x18
#define MBEDTLS_ASN1_UNIVERSAL_STRING        0x1C
#define MBEDTLS_ASN1_BMP_STRING              0x1E
#define MBEDTLS_ASN1_PRIMITIVE               0x00
#define MBEDTLS_ASN1_CONSTRUCTED             0x20
#define MBEDTLS_ASN1_CONTEXT_SPECIFIC        0x80

/** \} name DER constants */

/** Returns the size of the binary string, without the trailing \\0 */
#define MBEDTLS_OID_SIZE(x) (sizeof(x) - 1)

/**
 * \name ASN1 Error codes
 * These error codes are combined with other error codes for
 * higher error granularity.
 * e.g. X.509 and PKCS #7 error codes
 * ASN1 is a standard to specify data structures.
 * \{
 */
/** Out of data when parsing an ASN1 data structure. */
#define MBEDTLS_ERR_ASN1_OUT_OF_DATA                      -0x0060
/** ASN1 tag was of an unexpected value. */
#define MBEDTLS_ERR_ASN1_UNEXPECTED_TAG                   -0x0062
/** Error when trying to determine the length or invalid length. */
#define MBEDTLS_ERR_ASN1_INVALID_LENGTH                   -0x0064
/** Actual length differs from expected length. */
#define MBEDTLS_ERR_ASN1_LENGTH_MISMATCH                  -0x0066
/** Data is invalid. */
#define MBEDTLS_ERR_ASN1_INVALID_DATA                     -0x0068
/** Memory allocation failed */
#define MBEDTLS_ERR_ASN1_ALLOC_FAILED                     -0x006A
/** Buffer too small when writing ASN.1 data structure. */
#define MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    -0x006C

/** \} name ASN1 Error codes */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct mbedtls_asn1_buf {
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
    unsigned char p_arr[512]; //new_impl
}
mbedtls_asn1_buf;

/**
 * Container for a sequence or list of 'named' ASN.1 data items
 */
typedef struct mbedtls_asn1_named_data {
    mbedtls_asn1_buf oid;                   /**< The object identifier. */
    mbedtls_asn1_buf val;                   /**< The named value. */

    /** The next entry in the sequence.
     *
     * The details of memory management for named data sequences are not
     * documented and may change in future versions. Set this field to \p NULL
     * when initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct mbedtls_asn1_named_data *next;

    /** Merge next item into the current one?
     *
     * This field exists for the sake of Mbed TLS's X.509 certificate parsing
     * code and may change in future versions of the library.
     */
    unsigned char MBEDTLS_PRIVATE(next_merged);
}
mbedtls_asn1_named_data;

/**
 * Container for a sequence of ASN.1 items
 */
typedef struct mbedtls_asn1_sequence {
    mbedtls_asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */

    /** The next entry in the sequence.
     *
     * The details of memory management for sequences are not documented and
     * may change in future versions. Set this field to \p NULL when
     * initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct mbedtls_asn1_sequence *next;
}
mbedtls_asn1_sequence;

//asn1write.h
#define MBEDTLS_ASN1_CHK_ADD(g, f)                      \
    do                                                  \
    {                                                   \
        if ((ret = (f)) < 0)                         \
        return ret;                              \
        else                                            \
        (g) += ret;                                 \
    } while (0)



#endif