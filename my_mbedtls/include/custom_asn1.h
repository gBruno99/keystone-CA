#ifndef CUSTOM_ASN1_H
#define CUSTOM_ASN1_H
#include <stddef.h>
#include "custom_utils.h"
#include "custom_string.h"

//asn1.h
/**
 * \name DER constants
 * These constants comply with the DER encoded ASN.1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::custom_x509_buf.
 * \{
 */
#define CUSTOM_ASN1_BOOLEAN                 0x01
#define CUSTOM_ASN1_INTEGER                 0x02
#define CUSTOM_ASN1_BIT_STRING              0x03
#define CUSTOM_ASN1_OCTET_STRING            0x04
#define CUSTOM_ASN1_NULL                    0x05
#define CUSTOM_ASN1_OID                     0x06
#define CUSTOM_ASN1_ENUMERATED              0x0A
#define CUSTOM_ASN1_UTF8_STRING             0x0C
#define CUSTOM_ASN1_SEQUENCE                0x10
#define CUSTOM_ASN1_SET                     0x11
#define CUSTOM_ASN1_PRINTABLE_STRING        0x13
#define CUSTOM_ASN1_T61_STRING              0x14
#define CUSTOM_ASN1_IA5_STRING              0x16
#define CUSTOM_ASN1_UTC_TIME                0x17
#define CUSTOM_ASN1_GENERALIZED_TIME        0x18
#define CUSTOM_ASN1_UNIVERSAL_STRING        0x1C
#define CUSTOM_ASN1_BMP_STRING              0x1E
#define CUSTOM_ASN1_PRIMITIVE               0x00
#define CUSTOM_ASN1_CONSTRUCTED             0x20
#define CUSTOM_ASN1_CONTEXT_SPECIFIC        0x80

/*
 * Bit masks for each of the components of an ASN.1 tag as specified in
 * ITU X.690 (08/2015), section 8.1 "General rules for encoding",
 * paragraph 8.1.2.2:
 *
 * Bit  8     7   6   5          1
 *     +-------+-----+------------+
 *     | Class | P/C | Tag number |
 *     +-------+-----+------------+
 */
#define CUSTOM_ASN1_TAG_CLASS_MASK          0xC0
#define CUSTOM_ASN1_TAG_PC_MASK             0x20
#define CUSTOM_ASN1_TAG_VALUE_MASK          0x1F

/** \} name DER constants */

/** Returns the size of the binary string, without the trailing \\0 */
#define CUSTOM_OID_SIZE(x) (sizeof(x) - 1)

/**
 * Compares an custom_asn1_buf structure to a reference OID.
 *
 * Only works for 'defined' oid_str values (CUSTOM_OID_HMAC_SHA1), you cannot use a
 * 'unsigned char *oid' here!
 */
#define CUSTOM_OID_CMP(oid_str, oid_buf)                                   \
    ((CUSTOM_OID_SIZE(oid_str) != (oid_buf)->len) ||                \
     custom_memcmp((oid_str), (oid_buf)->p, (oid_buf)->len) != 0)

/**
 * \name ASN1 Error codes
 * These error codes are combined with other error codes for
 * higher error granularity.
 * e.g. X.509 and PKCS #7 error codes
 * ASN1 is a standard to specify data structures.
 * \{
 */
/** Out of data when parsing an ASN1 data structure. */
#define CUSTOM_ERR_ASN1_OUT_OF_DATA                      -0x0060
/** ASN1 tag was of an unexpected value. */
#define CUSTOM_ERR_ASN1_UNEXPECTED_TAG                   -0x0062
/** Error when trying to determine the length or invalid length. */
#define CUSTOM_ERR_ASN1_INVALID_LENGTH                   -0x0064
/** Actual length differs from expected length. */
#define CUSTOM_ERR_ASN1_LENGTH_MISMATCH                  -0x0066
/** Data is invalid. */
#define CUSTOM_ERR_ASN1_INVALID_DATA                     -0x0068
/** Memory allocation failed */
#define CUSTOM_ERR_ASN1_ALLOC_FAILED                     -0x006A
/** Buffer too small when writing ASN.1 data structure. */
#define CUSTOM_ERR_ASN1_BUF_TOO_SMALL                    -0x006C

/** \} name ASN1 Error codes */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct custom_asn1_buf {
    int tag;                /**< ASN1 type, e.g. CUSTOM_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
}
custom_asn1_buf;

typedef custom_asn1_buf custom_x509_buf_crt; // new_impl

/**
 * Container for ASN1 bit strings.
 */
typedef struct custom_asn1_bitstring {
    size_t len;                 /**< ASN1 length, in octets. */
    unsigned char unused_bits;  /**< Number of unused bits at the end of the string */
    unsigned char *p;           /**< Raw ASN1 data for the bit string */
}
custom_asn1_bitstring;

/**
 * Container for a sequence or list of 'named' ASN.1 data items
 */
typedef struct custom_asn1_named_data {
    custom_asn1_buf oid;                   /**< The object identifier. */
    custom_asn1_buf val;                   /**< The named value. */

    /** The next entry in the sequence.
     *
     * The details of memory management for named data sequences are not
     * documented and may change in future versions. Set this field to \p NULL
     * when initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct custom_asn1_named_data *next;

    /** Merge next item into the current one?
     *
     * This field exists for the sake of Mbed TLS's X.509 certificate parsing
     * code and may change in future versions of the library.
     */
    unsigned char CUSTOM_PRIVATE(next_merged);
}
custom_asn1_named_data;

/**
 * Container for a sequence of ASN.1 items
 */
typedef struct custom_asn1_sequence {
    custom_asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */

    /** The next entry in the sequence.
     *
     * The details of memory management for sequences are not documented and
     * may change in future versions. Set this field to \p NULL when
     * initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct custom_asn1_sequence *next;
}
custom_asn1_sequence;

//asn1write.h
#define CUSTOM_ASN1_CHK_ADD(g, f)                      \
    do                                                  \
    {                                                   \
        if ((ret = (f)) < 0)                         \
        return ret;                              \
        else                                            \
        (g) += ret;                                 \
    } while (0)

#define CUSTOM_ASN1_CHK_CLEANUP_ADD(g, f)                      \
    do                                                  \
    {                                                   \
        if ((ret = (f)) < 0)                         \
        goto cleanup;                              \
        else                                            \
        (g) += ret;                                 \
    } while (0)


#endif