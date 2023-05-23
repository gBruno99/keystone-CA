#ifndef CUSTOM_MBEDTLS_X509_H
#define CUSTOM_MBEDTLS_X509_H
#include "custom_utils.h"
#include "custom_oid.h"
#include "my_utils_2.h"

//x509.h
#define MBEDTLS_X509_MAX_INTERMEDIATE_CA   8

#define MBEDTLS_X509_MAX_DN_NAME_SIZE         256 /**< Maximum value size of a DN entry */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 *
 * Those are defined in oid.h as oid.c needs them in a data structure. Since
 * these were previously defined here, let's have aliases for compatibility.
 */
#define MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER   MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_KEY_USAGE                MBEDTLS_OID_X509_EXT_KEY_USAGE
#define MBEDTLS_X509_EXT_CERTIFICATE_POLICIES     MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES
#define MBEDTLS_X509_EXT_POLICY_MAPPINGS          MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS
#define MBEDTLS_X509_EXT_SUBJECT_ALT_NAME         MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME         /* Supported (DNS) */
#define MBEDTLS_X509_EXT_ISSUER_ALT_NAME          MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME
#define MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS  MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS
#define MBEDTLS_X509_EXT_BASIC_CONSTRAINTS        MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS        /* Supported */
#define MBEDTLS_X509_EXT_NAME_CONSTRAINTS         MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS
#define MBEDTLS_X509_EXT_POLICY_CONSTRAINTS       MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS
#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE       MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS  MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS
#define MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY       MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY
#define MBEDTLS_X509_EXT_FRESHEST_CRL             MBEDTLS_OID_X509_EXT_FRESHEST_CRL
#define MBEDTLS_X509_EXT_NS_CERT_TYPE             MBEDTLS_OID_X509_EXT_NS_CERT_TYPE

/**
 * \name X509 Error codes
 * \{
 */
/** Unavailable feature, e.g. RSA hashing/encryption combination. */
#define MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              -0x2080
/** Requested OID is unknown. */
#define MBEDTLS_ERR_X509_UNKNOWN_OID                      -0x2100
/** The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_X509_INVALID_FORMAT                   -0x2180
/** The CRT/CRL/CSR version element is invalid. */
#define MBEDTLS_ERR_X509_INVALID_VERSION                  -0x2200
/** The serial tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_SERIAL                   -0x2280
/** The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_ALG                      -0x2300
/** The name tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_NAME                     -0x2380
/** The date tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_DATE                     -0x2400
/** The signature tag or value invalid. */
#define MBEDTLS_ERR_X509_INVALID_SIGNATURE                -0x2480
/** The extension tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_EXTENSIONS               -0x2500
/** CRT/CRL/CSR has an unsupported version number. */
#define MBEDTLS_ERR_X509_UNKNOWN_VERSION                  -0x2580
/** Signature algorithm (oid) is unsupported. */
#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600
/** Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
#define MBEDTLS_ERR_X509_SIG_MISMATCH                     -0x2680
/** Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               -0x2700
/** Format not recognized as DER or PEM. */
#define MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780
/** Input invalid. */
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA                   -0x2800
/** Allocation of memory failed. */
#define MBEDTLS_ERR_X509_ALLOC_FAILED                     -0x2880
/** Read/write of file failed. */
#define MBEDTLS_ERR_X509_FILE_IO_ERROR                    -0x2900
/** Destination buffer is too small. */
#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 -0x2980
/** A fatal error occurred, eg the chain is too long or the vrfy callback failed. */
#define MBEDTLS_ERR_X509_FATAL_ERROR                      -0x3000
/** \} name X509 Error codes */

/**
 * \name X509 Verify codes
 * \{
 */
/* Reminder: update x509_crt_verify_strings[] in library/x509_crt.c */
#define MBEDTLS_X509_BADCERT_EXPIRED             0x01  /**< The certificate validity has expired. */
#define MBEDTLS_X509_BADCERT_REVOKED             0x02  /**< The certificate has been revoked (is on a CRL). */
#define MBEDTLS_X509_BADCERT_CN_MISMATCH         0x04  /**< The certificate Common Name (CN) does not match with the expected CN. */
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED         0x08  /**< The certificate is not correctly signed by the trusted CA. */
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED          0x10  /**< The CRL is not correctly signed by the trusted CA. */
#define MBEDTLS_X509_BADCRL_EXPIRED              0x20  /**< The CRL is expired. */
#define MBEDTLS_X509_BADCERT_MISSING             0x40  /**< Certificate was missing. */
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY         0x80  /**< Certificate verification was skipped. */
#define MBEDTLS_X509_BADCERT_OTHER             0x0100  /**< Other reason (can be used by verify callback) */
#define MBEDTLS_X509_BADCERT_FUTURE            0x0200  /**< The certificate validity starts in the future. */
#define MBEDTLS_X509_BADCRL_FUTURE             0x0400  /**< The CRL is from the future */
#define MBEDTLS_X509_BADCERT_KEY_USAGE         0x0800  /**< Usage does not match the keyUsage extension. */
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE     0x1000  /**< Usage does not match the extendedKeyUsage extension. */
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE      0x2000  /**< Usage does not match the nsCertType extension. */
#define MBEDTLS_X509_BADCERT_BAD_MD            0x4000  /**< The certificate is signed with an unacceptable hash. */
#define MBEDTLS_X509_BADCERT_BAD_PK            0x8000  /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define MBEDTLS_X509_BADCERT_BAD_KEY         0x010000  /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
#define MBEDTLS_X509_BADCRL_BAD_MD           0x020000  /**< The CRL is signed with an unacceptable hash. */
#define MBEDTLS_X509_BADCRL_BAD_PK           0x040000  /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define MBEDTLS_X509_BADCRL_BAD_KEY          0x080000  /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

/** \} name X509 Verify codes */

/*
 * X.509 v3 Subject Alternative Name types.
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER
 */
#define MBEDTLS_X509_SAN_OTHER_NAME                      0
#define MBEDTLS_X509_SAN_RFC822_NAME                     1
#define MBEDTLS_X509_SAN_DNS_NAME                        2
#define MBEDTLS_X509_SAN_X400_ADDRESS_NAME               3
#define MBEDTLS_X509_SAN_DIRECTORY_NAME                  4
#define MBEDTLS_X509_SAN_EDI_PARTY_NAME                  5
#define MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER     6
#define MBEDTLS_X509_SAN_IP_ADDRESS                      7
#define MBEDTLS_X509_SAN_REGISTERED_ID                   8

/*
 * X.509 v3 Key Usage Extension flags
 * Reminder: update mbedtls_x509_info_key_usage() when adding new flags.
 */
#define MBEDTLS_X509_KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
#define MBEDTLS_X509_KU_NON_REPUDIATION              (0x40)  /* bit 1 */
#define MBEDTLS_X509_KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
#define MBEDTLS_X509_KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
#define MBEDTLS_X509_KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
#define MBEDTLS_X509_KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
#define MBEDTLS_X509_KU_CRL_SIGN                     (0x02)  /* bit 6 */
#define MBEDTLS_X509_KU_ENCIPHER_ONLY                (0x01)  /* bit 7 */
#define MBEDTLS_X509_KU_DECIPHER_ONLY              (0x8000)  /* bit 8 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf mbedtls_x509_buf;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef mbedtls_asn1_named_data mbedtls_x509_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef mbedtls_asn1_sequence mbedtls_x509_sequence;

/** Container for date and time (precision in seconds). */
typedef struct mbedtls_x509_time {
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
}
mbedtls_x509_time;

//x509_crt.h
#define MBEDTLS_X509_CRT_VERSION_1              0
#define MBEDTLS_X509_CRT_VERSION_2              1
#define MBEDTLS_X509_CRT_VERSION_3              2

#define MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN 20
#define MBEDTLS_X509_RFC5280_UTC_TIME_LEN   15

/**
 * Container for writing a certificate (CRT)
 */
typedef struct mbedtls_x509write_cert {
    int MBEDTLS_PRIVATE(version);
    unsigned char MBEDTLS_PRIVATE(serial)[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t MBEDTLS_PRIVATE(serial_len);
    mbedtls_pk_context *MBEDTLS_PRIVATE(subject_key);
    mbedtls_pk_context *MBEDTLS_PRIVATE(issuer_key);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(subject);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(issuer);
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_alg);
    char MBEDTLS_PRIVATE(not_before)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char MBEDTLS_PRIVATE(not_after)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(extensions);
}
mbedtls_x509write_cert;


/**
 * Container for an X.509 certificate. The certificate may be chained.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct mbedtls_x509_crt {
    int MBEDTLS_PRIVATE(own_buffer);                     /**< Indicates if \c raw is owned
                                                          *   by the structure or not.        */
    mbedtls_x509_buf raw;               /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;                /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
    mbedtls_x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
    mbedtls_x509_buf sig_oid;           /**< Signature algorithm, e.g. sha1RSA */

    mbedtls_x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    mbedtls_x509_buf subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

    mbedtls_x509_name issuer;           /**< The parsed issuer data (named information object). */
    mbedtls_x509_name subject;          /**< The parsed subject data (named information object). */

    mbedtls_x509_time valid_from;       /**< Start time of certificate validity. */
    mbedtls_x509_time valid_to;         /**< End time of certificate validity. */

    mbedtls_x509_buf pk_raw;
    mbedtls_pk_context pk;              /**< Container for the public key context. */

    mbedtls_x509_buf issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
    mbedtls_x509_buf subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
    mbedtls_x509_buf v3_ext;            /**< Optional X.509 v3 extensions.  */
    mbedtls_x509_buf hash; //new_impl
    mbedtls_x509_sequence subject_alt_names;    /**< Optional list of raw entries of Subject Alternative Names extension (currently only dNSName, uniformResourceIdentifier and OtherName are listed). */

    mbedtls_x509_sequence certificate_policies; /**< Optional list of certificate policies (Only anyPolicy is printed and enforced, however the rest of the policies are still listed). */

    int MBEDTLS_PRIVATE(ext_types);              /**< Bit string containing detected and parsed extensions */
    int MBEDTLS_PRIVATE(ca_istrue);              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int MBEDTLS_PRIVATE(max_pathlen);            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

    unsigned int MBEDTLS_PRIVATE(key_usage);     /**< Optional key usage extension value: See the values in x509.h */

    mbedtls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

    unsigned char MBEDTLS_PRIVATE(ns_cert_type); /**< Optional Netscape certificate type extension value: See the values in x509.h */

    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);               /**< Signature: hash of the tbs part signed with the private key. */
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next certificate in the linked list that constitutes the CA chain.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crt *next;
}
mbedtls_x509_crt;

/**
 * Build flag from an algorithm/curve identifier (pk, md, ecp)
 * Since 0 is always XXX_NONE, ignore it.
 */
#define MBEDTLS_X509_ID_FLAG(id)   (1 << ((id) - 1))

/**
 * Security profile for certificate verification.
 *
 * All lists are bitfields, built by ORing flags from MBEDTLS_X509_ID_FLAG().
 *
 * The fields of this structure are part of the public API and can be
 * manipulated directly by applications. Future versions of the library may
 * add extra fields or reorder existing fields.
 *
 * You can create custom profiles by starting from a copy of
 * an existing profile, such as mbedtls_x509_crt_profile_default or
 * mbedtls_x509_ctr_profile_none and then tune it to your needs.
 *
 * For example to allow SHA-224 in addition to the default:
 *
 *  mbedtls_x509_crt_profile my_profile = mbedtls_x509_crt_profile_default;
 *  my_profile.allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 );
 *
 * Or to allow only RSA-3072+ with SHA-256:
 *
 *  mbedtls_x509_crt_profile my_profile = mbedtls_x509_crt_profile_none;
 *  my_profile.allowed_mds = MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 );
 *  my_profile.allowed_pks = MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_RSA );
 *  my_profile.rsa_min_bitlen = 3072;
 */
typedef struct mbedtls_x509_crt_profile {
    uint32_t allowed_mds;       /**< MDs for signatures         */
    uint32_t allowed_pks;       /**< PK algs for public keys;
                                 *   this applies to all certificates
                                 *   in the provided chain.     */
    uint32_t allowed_curves;    /**< Elliptic curves for ECDSA  */
    uint32_t rsa_min_bitlen;    /**< Minimum size for RSA keys  */
}
mbedtls_x509_crt_profile;

/**
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
    mbedtls_x509_crt *MBEDTLS_PRIVATE(crt);
    uint32_t MBEDTLS_PRIVATE(flags);
} mbedtls_x509_crt_verify_chain_item;

/**
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE  (MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2)

/**
 * Verification chain as built by \c mbedtls_crt_verify_chain()
 */
typedef struct {
    mbedtls_x509_crt_verify_chain_item MBEDTLS_PRIVATE(items)[MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE];
    unsigned MBEDTLS_PRIVATE(len);

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* This stores the list of potential trusted signers obtained from
     * the CA callback used for the CRT verification, if configured.
     * We must track it somewhere because the callback passes its
     * ownership to the caller. */
    mbedtls_x509_crt *MBEDTLS_PRIVATE(trust_ca_cb_result);
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
} mbedtls_x509_crt_verify_chain;

/* Now we can declare functions that take a pointer to that */
typedef void mbedtls_x509_crt_restart_ctx;

/**
 * \brief          The type of certificate extension callbacks.
 *
 *                 Callbacks of this type are passed to and used by the
 *                 mbedtls_x509_crt_parse_der_with_ext_cb() routine when
 *                 it encounters either an unsupported extension or a
 *                 "certificate policies" extension containing any
 *                 unsupported certificate policies.
 *                 Future versions of the library may invoke the callback
 *                 in other cases, if and when the need arises.
 *
 * \param p_ctx    An opaque context passed to the callback.
 * \param crt      The certificate being parsed.
 * \param oid      The OID of the extension.
 * \param critical Whether the extension is critical.
 * \param p        Pointer to the start of the extension value
 *                 (the content of the OCTET STRING).
 * \param end      End of extension value.
 *
 * \note           The callback must fail and return a negative error code
 *                 if it can not parse or does not support the extension.
 *                 When the callback fails to parse a critical extension
 *                 mbedtls_x509_crt_parse_der_with_ext_cb() also fails.
 *                 When the callback fails to parse a non critical extension
 *                 mbedtls_x509_crt_parse_der_with_ext_cb() simply skips
 *                 the extension and continues parsing.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
typedef int (*mbedtls_x509_crt_ext_cb_t)(void *p_ctx,
                                         mbedtls_x509_crt const *crt,
                                         mbedtls_x509_buf const *oid,
                                         int critical,
                                         const unsigned char *p,
                                         const unsigned char *end);

/**
 * \brief               The type of trusted certificate callbacks.
 *
 *                      Callbacks of this type are passed to and used by the CRT
 *                      verification routine mbedtls_x509_crt_verify_with_ca_cb()
 *                      when looking for trusted signers of a given certificate.
 *
 *                      On success, the callback returns a list of trusted
 *                      certificates to be considered as potential signers
 *                      for the input certificate.
 *
 * \param p_ctx         An opaque context passed to the callback.
 * \param child         The certificate for which to search a potential signer.
 *                      This will point to a readable certificate.
 * \param candidate_cas The address at which to store the address of the first
 *                      entry in the generated linked list of candidate signers.
 *                      This will not be \c NULL.
 *
 * \note                The callback must only return a non-zero value on a
 *                      fatal error. If, in contrast, the search for a potential
 *                      signer completes without a single candidate, the
 *                      callback must return \c 0 and set \c *candidate_cas
 *                      to \c NULL.
 *
 * \return              \c 0 on success. In this case, \c *candidate_cas points
 *                      to a heap-allocated linked list of instances of
 *                      ::mbedtls_x509_crt, and ownership of this list is passed
 *                      to the caller.
 * \return              A negative error code on failure.
 */
typedef int (*mbedtls_x509_crt_ca_cb_t)(void *p_ctx,
                                        mbedtls_x509_crt const *child,
                                        mbedtls_x509_crt **candidate_cas);

// x509_crl.h

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct mbedtls_x509_crl_entry {
    /** Direct access to the whole entry inside the containing buffer. */
    mbedtls_x509_buf raw;
    /** The serial number of the revoked certificate. */
    mbedtls_x509_buf serial;
    /** The revocation date of this entry. */
    mbedtls_x509_time revocation_date;
    /** Direct access to the list of CRL entry extensions
     * (an ASN.1 constructed sequence).
     *
     * If there are no extensions, `entry_ext.len == 0` and
     * `entry_ext.p == NULL`. */
    mbedtls_x509_buf entry_ext;

    /** Next element in the linked list of entries.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crl_entry *next;
}
mbedtls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct mbedtls_x509_crl {
    mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */

    mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    mbedtls_x509_time this_update;
    mbedtls_x509_time next_update;

    mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    mbedtls_x509_buf crl_ext;

    mbedtls_x509_buf MBEDTLS_PRIVATE(sig_oid2);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next element in the linked list of CRL.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crl *next;
}
mbedtls_x509_crl;

#endif