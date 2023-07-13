#ifndef CUSTOM_X509_H
#define CUSTOM_X509_H
#include "custom_utils.h"
#include "custom_oid.h"
#include "custom_utils_2.h"

// custom new_impl
#define NONCE_LEN               32
#define ATTESTATION_PROOF_LEN   64

//x509.h
#define CUSTOM_X509_MAX_INTERMEDIATE_CA   8

#define CUSTOM_X509_MAX_DN_NAME_SIZE         256 /**< Maximum value size of a DN entry */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 *
 * Those are defined in oid.h as oid.c needs them in a data structure. Since
 * these were previously defined here, let's have aliases for compatibility.
 */
#define CUSTOM_X509_EXT_AUTHORITY_KEY_IDENTIFIER CUSTOM_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
#define CUSTOM_X509_EXT_SUBJECT_KEY_IDENTIFIER   CUSTOM_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
#define CUSTOM_X509_EXT_KEY_USAGE                CUSTOM_OID_X509_EXT_KEY_USAGE
#define CUSTOM_X509_EXT_CERTIFICATE_POLICIES     CUSTOM_OID_X509_EXT_CERTIFICATE_POLICIES
#define CUSTOM_X509_EXT_POLICY_MAPPINGS          CUSTOM_OID_X509_EXT_POLICY_MAPPINGS
#define CUSTOM_X509_EXT_SUBJECT_ALT_NAME         CUSTOM_OID_X509_EXT_SUBJECT_ALT_NAME         /* Supported (DNS) */
#define CUSTOM_X509_EXT_ISSUER_ALT_NAME          CUSTOM_OID_X509_EXT_ISSUER_ALT_NAME
#define CUSTOM_X509_EXT_SUBJECT_DIRECTORY_ATTRS  CUSTOM_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS
#define CUSTOM_X509_EXT_BASIC_CONSTRAINTS        CUSTOM_OID_X509_EXT_BASIC_CONSTRAINTS        /* Supported */
#define CUSTOM_X509_EXT_NAME_CONSTRAINTS         CUSTOM_OID_X509_EXT_NAME_CONSTRAINTS
#define CUSTOM_X509_EXT_POLICY_CONSTRAINTS       CUSTOM_OID_X509_EXT_POLICY_CONSTRAINTS
#define CUSTOM_X509_EXT_EXTENDED_KEY_USAGE       CUSTOM_OID_X509_EXT_EXTENDED_KEY_USAGE
#define CUSTOM_X509_EXT_CRL_DISTRIBUTION_POINTS  CUSTOM_OID_X509_EXT_CRL_DISTRIBUTION_POINTS
#define CUSTOM_X509_EXT_INIHIBIT_ANYPOLICY       CUSTOM_OID_X509_EXT_INIHIBIT_ANYPOLICY
#define CUSTOM_X509_EXT_FRESHEST_CRL             CUSTOM_OID_X509_EXT_FRESHEST_CRL
#define CUSTOM_X509_EXT_NS_CERT_TYPE             CUSTOM_OID_X509_EXT_NS_CERT_TYPE
#define CUSTOM_X509_EXT_NONCE                    CUSTOM_OID_X509_EXT_NONCE                // new_impl  
#define CUSTOM_X509_EXT_DICE_CERTS               CUSTOM_OID_X509_EXT_DICE_CERTS           // new_impl
#define CUSTOM_X509_EXT_ATTESTATION_PROOF        CUSTOM_OID_X509_EXT_ATTESTATION_PROOF    // new_impl

/**
 * \name X509 Error codes
 * \{
 */
/** Unavailable feature, e.g. RSA hashing/encryption combination. */
#define CUSTOM_ERR_X509_FEATURE_UNAVAILABLE              -0x2080
/** Requested OID is unknown. */
#define CUSTOM_ERR_X509_UNKNOWN_OID                      -0x2100
/** The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define CUSTOM_ERR_X509_INVALID_FORMAT                   -0x2180
/** The CRT/CRL/CSR version element is invalid. */
#define CUSTOM_ERR_X509_INVALID_VERSION                  -0x2200
/** The serial tag or value is invalid. */
#define CUSTOM_ERR_X509_INVALID_SERIAL                   -0x2280
/** The algorithm tag or value is invalid. */
#define CUSTOM_ERR_X509_INVALID_ALG                      -0x2300
/** The name tag or value is invalid. */
#define CUSTOM_ERR_X509_INVALID_NAME                     -0x2380
/** The date tag or value is invalid. */
#define CUSTOM_ERR_X509_INVALID_DATE                     -0x2400
/** The signature tag or value invalid. */
#define CUSTOM_ERR_X509_INVALID_SIGNATURE                -0x2480
/** The extension tag or value is invalid. */
#define CUSTOM_ERR_X509_INVALID_EXTENSIONS               -0x2500
/** CRT/CRL/CSR has an unsupported version number. */
#define CUSTOM_ERR_X509_UNKNOWN_VERSION                  -0x2580
/** Signature algorithm (oid) is unsupported. */
#define CUSTOM_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600
/** Signature algorithms do not match. (see \c ::custom_x509_crt sig_oid) */
#define CUSTOM_ERR_X509_SIG_MISMATCH                     -0x2680
/** Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define CUSTOM_ERR_X509_CERT_VERIFY_FAILED               -0x2700
/** Format not recognized as DER or PEM. */
#define CUSTOM_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780
/** Input invalid. */
#define CUSTOM_ERR_X509_BAD_INPUT_DATA                   -0x2800
/** Allocation of memory failed. */
#define CUSTOM_ERR_X509_ALLOC_FAILED                     -0x2880
/** Read/write of file failed. */
#define CUSTOM_ERR_X509_FILE_IO_ERROR                    -0x2900
/** Destination buffer is too small. */
#define CUSTOM_ERR_X509_BUFFER_TOO_SMALL                 -0x2980
/** A fatal error occurred, eg the chain is too long or the vrfy callback failed. */
#define CUSTOM_ERR_X509_FATAL_ERROR                      -0x3000
/** \} name X509 Error codes */

/**
 * \name X509 Verify codes
 * \{
 */
/* Reminder: update x509_crt_verify_strings[] in library/x509_crt.c */
#define CUSTOM_X509_BADCERT_EXPIRED             0x01  /**< The certificate validity has expired. */
#define CUSTOM_X509_BADCERT_REVOKED             0x02  /**< The certificate has been revoked (is on a CRL). */
#define CUSTOM_X509_BADCERT_CN_MISMATCH         0x04  /**< The certificate Common Name (CN) does not match with the expected CN. */
#define CUSTOM_X509_BADCERT_NOT_TRUSTED         0x08  /**< The certificate is not correctly signed by the trusted CA. */
#define CUSTOM_X509_BADCRL_NOT_TRUSTED          0x10  /**< The CRL is not correctly signed by the trusted CA. */
#define CUSTOM_X509_BADCRL_EXPIRED              0x20  /**< The CRL is expired. */
#define CUSTOM_X509_BADCERT_MISSING             0x40  /**< Certificate was missing. */
#define CUSTOM_X509_BADCERT_SKIP_VERIFY         0x80  /**< Certificate verification was skipped. */
#define CUSTOM_X509_BADCERT_OTHER             0x0100  /**< Other reason (can be used by verify callback) */
#define CUSTOM_X509_BADCERT_FUTURE            0x0200  /**< The certificate validity starts in the future. */
#define CUSTOM_X509_BADCRL_FUTURE             0x0400  /**< The CRL is from the future */
#define CUSTOM_X509_BADCERT_KEY_USAGE         0x0800  /**< Usage does not match the keyUsage extension. */
#define CUSTOM_X509_BADCERT_EXT_KEY_USAGE     0x1000  /**< Usage does not match the extendedKeyUsage extension. */
#define CUSTOM_X509_BADCERT_NS_CERT_TYPE      0x2000  /**< Usage does not match the nsCertType extension. */
#define CUSTOM_X509_BADCERT_BAD_MD            0x4000  /**< The certificate is signed with an unacceptable hash. */
#define CUSTOM_X509_BADCERT_BAD_PK            0x8000  /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define CUSTOM_X509_BADCERT_BAD_KEY         0x010000  /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
#define CUSTOM_X509_BADCRL_BAD_MD           0x020000  /**< The CRL is signed with an unacceptable hash. */
#define CUSTOM_X509_BADCRL_BAD_PK           0x040000  /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define CUSTOM_X509_BADCRL_BAD_KEY          0x080000  /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

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
#define CUSTOM_X509_SAN_OTHER_NAME                      0
#define CUSTOM_X509_SAN_RFC822_NAME                     1
#define CUSTOM_X509_SAN_DNS_NAME                        2
#define CUSTOM_X509_SAN_X400_ADDRESS_NAME               3
#define CUSTOM_X509_SAN_DIRECTORY_NAME                  4
#define CUSTOM_X509_SAN_EDI_PARTY_NAME                  5
#define CUSTOM_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER     6
#define CUSTOM_X509_SAN_IP_ADDRESS                      7
#define CUSTOM_X509_SAN_REGISTERED_ID                   8

/*
 * X.509 v3 Key Usage Extension flags
 * Reminder: update custom_x509_info_key_usage() when adding new flags.
 */
#define CUSTOM_X509_KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
#define CUSTOM_X509_KU_NON_REPUDIATION              (0x40)  /* bit 1 */
#define CUSTOM_X509_KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
#define CUSTOM_X509_KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
#define CUSTOM_X509_KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
#define CUSTOM_X509_KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
#define CUSTOM_X509_KU_CRL_SIGN                     (0x02)  /* bit 6 */
#define CUSTOM_X509_KU_ENCIPHER_ONLY                (0x01)  /* bit 7 */
#define CUSTOM_X509_KU_DECIPHER_ONLY              (0x8000)  /* bit 8 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef custom_asn1_buf custom_x509_buf;

/**
 * Container for ASN1 bit strings.
 */
typedef custom_asn1_bitstring custom_x509_bitstring;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef custom_asn1_named_data custom_x509_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef custom_asn1_sequence custom_x509_sequence;

/** Container for date and time (precision in seconds). */
typedef struct custom_x509_time {
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
}
custom_x509_time;

/**
 * From RFC 5280 section 4.2.1.6:
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * Future versions of the library may add new fields to this structure or
 * to its embedded union and structure.
 */
typedef struct custom_x509_san_other_name {
    /**
     * The type_id is an OID as defined in RFC 5280.
     * To check the value of the type id, you should use
     * \p CUSTOM_OID_CMP with a known OID custom_x509_buf.
     */
    custom_x509_buf type_id;                   /**< The type id. */
    union {
        /**
         * From RFC 4108 section 5:
         * HardwareModuleName ::= SEQUENCE {
         *                         hwType OBJECT IDENTIFIER,
         *                         hwSerialNum OCTET STRING }
         */
        struct {
            custom_x509_buf oid;               /**< The object identifier. */
            custom_x509_buf val;               /**< The named value. */
        }
        hardware_module_name;
    }
    value;
}
custom_x509_san_other_name;

/**
 * A structure for holding the parsed Subject Alternative Name,
 * according to type.
 *
 * Future versions of the library may add new fields to this structure or
 * to its embedded union and structure.
 */
typedef struct custom_x509_subject_alternative_name {
    int type;                              /**< The SAN type, value of CUSTOM_X509_SAN_XXX. */
    union {
        custom_x509_san_other_name other_name; /**< The otherName supported type. */
        custom_x509_name directory_name;
        custom_x509_buf unstructured_name; /**< The buffer for the unstructured types. rfc822Name, dnsName and uniformResourceIdentifier are currently supported. */
    }
    san; /**< A union of the supported SAN types */
}
custom_x509_subject_alternative_name;

//x509_crt.h
#define CUSTOM_X509_CRT_VERSION_1              0
#define CUSTOM_X509_CRT_VERSION_2              1
#define CUSTOM_X509_CRT_VERSION_3              2

#define CUSTOM_X509_RFC5280_MAX_SERIAL_LEN 20
#define CUSTOM_X509_RFC5280_UTC_TIME_LEN   15

/**
 * Container for writing a certificate (CRT)
 */
typedef struct custom_x509write_cert {
    int CUSTOM_PRIVATE(version);
    unsigned char CUSTOM_PRIVATE(serial)[CUSTOM_X509_RFC5280_MAX_SERIAL_LEN];
    size_t CUSTOM_PRIVATE(serial_len);
    custom_pk_context *CUSTOM_PRIVATE(subject_key);
    custom_pk_context *CUSTOM_PRIVATE(issuer_key);
    custom_asn1_named_data *CUSTOM_PRIVATE(subject);
    custom_asn1_named_data *CUSTOM_PRIVATE(issuer);
    custom_md_type_t CUSTOM_PRIVATE(md_alg);
    char CUSTOM_PRIVATE(not_before)[CUSTOM_X509_RFC5280_UTC_TIME_LEN + 1];
    char CUSTOM_PRIVATE(not_after)[CUSTOM_X509_RFC5280_UTC_TIME_LEN + 1];
    custom_asn1_named_data *CUSTOM_PRIVATE(extensions);
}
custom_x509write_cert;


/**
 * Container for an X.509 certificate. The certificate may be chained.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct custom_x509_crt {
    int CUSTOM_PRIVATE(own_buffer);                     /**< Indicates if \c raw is owned
                                                          *   by the structure or not.        */
    custom_x509_buf raw;               /**< The raw certificate data (DER). */
    custom_x509_buf tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;                /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
    custom_x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
    custom_x509_buf sig_oid;           /**< Signature algorithm, e.g. sha1RSA */

    custom_x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    custom_x509_buf subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

    custom_x509_name issuer;           /**< The parsed issuer data (named information object). */
    custom_x509_name subject;          /**< The parsed subject data (named information object). */

    custom_x509_time valid_from;       /**< Start time of certificate validity. */
    custom_x509_time valid_to;         /**< End time of certificate validity. */

    custom_x509_buf pk_raw;
    custom_pk_context pk;              /**< Container for the public key context. */

    custom_x509_buf issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
    custom_x509_buf subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
    custom_x509_buf v3_ext;            /**< Optional X.509 v3 extensions.  */
    custom_x509_buf hash; //new_impl
    custom_x509_sequence subject_alt_names;    /**< Optional list of raw entries of Subject Alternative Names extension (currently only dNSName, uniformResourceIdentifier and OtherName are listed). */

    custom_x509_sequence certificate_policies; /**< Optional list of certificate policies (Only anyPolicy is printed and enforced, however the rest of the policies are still listed). */

    int CUSTOM_PRIVATE(ext_types);              /**< Bit string containing detected and parsed extensions */
    int CUSTOM_PRIVATE(ca_istrue);              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int CUSTOM_PRIVATE(max_pathlen);            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

    unsigned int CUSTOM_PRIVATE(key_usage);     /**< Optional key usage extension value: See the values in x509.h */

    custom_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

    unsigned char CUSTOM_PRIVATE(ns_cert_type); /**< Optional Netscape certificate type extension value: See the values in x509.h */

    custom_x509_buf CUSTOM_PRIVATE(sig);               /**< Signature: hash of the tbs part signed with the private key. */
    custom_md_type_t CUSTOM_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. CUSTOM_MD_SHA256 */
    custom_pk_type_t CUSTOM_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. CUSTOM_PK_RSA */
    void *CUSTOM_PRIVATE(sig_opts);             /**< Signature options to be passed to custom_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next certificate in the linked list that constitutes the CA chain.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct custom_x509_crt *next;
}
custom_x509_crt;

/**
 * Build flag from an algorithm/curve identifier (pk, md, ecp)
 * Since 0 is always XXX_NONE, ignore it.
 */
#define CUSTOM_X509_ID_FLAG(id)   (1 << ((id) - 1))

/**
 * Security profile for certificate verification.
 *
 * All lists are bitfields, built by ORing flags from CUSTOM_X509_ID_FLAG().
 *
 * The fields of this structure are part of the public API and can be
 * manipulated directly by applications. Future versions of the library may
 * add extra fields or reorder existing fields.
 *
 * You can create custom profiles by starting from a copy of
 * an existing profile, such as custom_x509_crt_profile_default or
 * custom_x509_ctr_profile_none and then tune it to your needs.
 *
 * For example to allow SHA-224 in addition to the default:
 *
 *  custom_x509_crt_profile custom_profile = custom_x509_crt_profile_default;
 *  custom_profile.allowed_mds |= CUSTOM_X509_ID_FLAG( CUSTOM_MD_SHA224 );
 *
 * Or to allow only RSA-3072+ with SHA-256:
 *
 *  custom_x509_crt_profile custom_profile = custom_x509_crt_profile_none;
 *  custom_profile.allowed_mds = CUSTOM_X509_ID_FLAG( CUSTOM_MD_SHA256 );
 *  custom_profile.allowed_pks = CUSTOM_X509_ID_FLAG( CUSTOM_PK_RSA );
 *  custom_profile.rsa_min_bitlen = 3072;
 */
typedef struct custom_x509_crt_profile {
    uint32_t allowed_mds;       /**< MDs for signatures         */
    uint32_t allowed_pks;       /**< PK algs for public keys;
                                 *   this applies to all certificates
                                 *   in the provided chain.     */
    uint32_t allowed_curves;    /**< Elliptic curves for ECDSA  */
    uint32_t rsa_min_bitlen;    /**< Minimum size for RSA keys  */
}
custom_x509_crt_profile;

/**
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
    custom_x509_crt *CUSTOM_PRIVATE(crt);
    uint32_t CUSTOM_PRIVATE(flags);
} custom_x509_crt_verify_chain_item;

/**
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define CUSTOM_X509_MAX_VERIFY_CHAIN_SIZE  (CUSTOM_X509_MAX_INTERMEDIATE_CA + 2)

/**
 * Verification chain as built by \c custom_crt_verify_chain()
 */
typedef struct {
    custom_x509_crt_verify_chain_item CUSTOM_PRIVATE(items)[CUSTOM_X509_MAX_VERIFY_CHAIN_SIZE];
    unsigned CUSTOM_PRIVATE(len);

#if defined(CUSTOM_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* This stores the list of potential trusted signers obtained from
     * the CA callback used for the CRT verification, if configured.
     * We must track it somewhere because the callback passes its
     * ownership to the caller. */
    custom_x509_crt *CUSTOM_PRIVATE(trust_ca_cb_result);
#endif /* CUSTOM_X509_TRUSTED_CERTIFICATE_CALLBACK */
} custom_x509_crt_verify_chain;

/* Now we can declare functions that take a pointer to that */
typedef void custom_x509_crt_restart_ctx;

/**
 * \brief          The type of certificate extension callbacks.
 *
 *                 Callbacks of this type are passed to and used by the
 *                 custom_x509_crt_parse_der_with_ext_cb() routine when
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
 *                 custom_x509_crt_parse_der_with_ext_cb() also fails.
 *                 When the callback fails to parse a non critical extension
 *                 custom_x509_crt_parse_der_with_ext_cb() simply skips
 *                 the extension and continues parsing.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
typedef int (*custom_x509_crt_ext_cb_t)(void *p_ctx,
                                         custom_x509_crt const *crt,
                                         custom_x509_buf const *oid,
                                         int critical,
                                         const unsigned char *p,
                                         const unsigned char *end);

/**
 * \brief               The type of trusted certificate callbacks.
 *
 *                      Callbacks of this type are passed to and used by the CRT
 *                      verification routine custom_x509_crt_verify_with_ca_cb()
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
 *                      ::custom_x509_crt, and ownership of this list is passed
 *                      to the caller.
 * \return              A negative error code on failure.
 */
typedef int (*custom_x509_crt_ca_cb_t)(void *p_ctx,
                                        custom_x509_crt const *child,
                                        custom_x509_crt **candidate_cas);

// x509_crl.h

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct custom_x509_crl_entry {
    /** Direct access to the whole entry inside the containing buffer. */
    custom_x509_buf raw;
    /** The serial number of the revoked certificate. */
    custom_x509_buf serial;
    /** The revocation date of this entry. */
    custom_x509_time revocation_date;
    /** Direct access to the list of CRL entry extensions
     * (an ASN.1 constructed sequence).
     *
     * If there are no extensions, `entry_ext.len == 0` and
     * `entry_ext.p == NULL`. */
    custom_x509_buf entry_ext;

    /** Next element in the linked list of entries.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct custom_x509_crl_entry *next;
}
custom_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct custom_x509_crl {
    custom_x509_buf raw;           /**< The raw certificate data (DER). */
    custom_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    custom_x509_buf sig_oid;       /**< CRL signature type identifier */

    custom_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    custom_x509_name issuer;       /**< The parsed issuer data (named information object). */

    custom_x509_time this_update;
    custom_x509_time next_update;

    custom_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    custom_x509_buf crl_ext;

    custom_x509_buf CUSTOM_PRIVATE(sig_oid2);
    custom_x509_buf CUSTOM_PRIVATE(sig);
    custom_md_type_t CUSTOM_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. CUSTOM_MD_SHA256 */
    custom_pk_type_t CUSTOM_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. CUSTOM_PK_RSA */
    void *CUSTOM_PRIVATE(sig_opts);             /**< Signature options to be passed to custom_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next element in the linked list of CRL.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct custom_x509_crl *next;
}
custom_x509_crl;

// x509_csr.h
/**
 * Certificate Signing Request (CSR) structure.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields point to is unspecified.
 */
typedef struct custom_x509_csr {
    custom_x509_buf raw;           /**< The raw CSR data (DER). */
    custom_x509_buf cri;           /**< The raw CertificateRequestInfo body (DER). */

    int version;            /**< CSR version (1=v1). */

    custom_x509_buf  subject_raw;  /**< The raw subject data (DER). */
    custom_x509_name subject;      /**< The parsed subject data (named information object). */

    custom_pk_context pk;          /**< Container for the public key context. */

    unsigned int key_usage;     /**< Optional key usage extension value: See the values in x509.h */
    unsigned char ns_cert_type; /**< Optional Netscape certificate type extension value: See the values in x509.h */
    custom_x509_sequence subject_alt_names;    /**< Optional list of raw entries of Subject Alternative Names extension (currently only dNSName and OtherName are listed). */

    custom_x509_crt cert_chain;            // new_impl
    custom_x509_buf nonce;                 // new_impl
    custom_x509_buf attestation_proof;     // new_impl

    int CUSTOM_PRIVATE(ext_types);              /**< Bit string containing detected and parsed extensions */

    custom_x509_buf sig_oid;
    custom_x509_buf CUSTOM_PRIVATE(sig);
    custom_md_type_t CUSTOM_PRIVATE(sig_md);       /**< Internal representation of the MD algorithm of the signature algorithm, e.g. CUSTOM_MD_SHA256 */
    custom_pk_type_t CUSTOM_PRIVATE(sig_pk);       /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. CUSTOM_PK_RSA */
    void *CUSTOM_PRIVATE(sig_opts);         /**< Signature options to be passed to custom_pk_verify_ext(), e.g. for RSASSA-PSS */
}
custom_x509_csr;

/**
 * Container for writing a CSR
 */
typedef struct custom_x509write_csr {
    custom_pk_context *CUSTOM_PRIVATE(key);
    custom_asn1_named_data *CUSTOM_PRIVATE(subject);
    custom_md_type_t CUSTOM_PRIVATE(md_alg);
    custom_asn1_named_data *CUSTOM_PRIVATE(extensions);
}
custom_x509write_csr;

typedef struct custom_x509_san_list {
    custom_x509_subject_alternative_name node;
    struct custom_x509_san_list *next;
}
custom_x509_san_list;

#endif