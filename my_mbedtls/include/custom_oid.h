#ifndef CUSTOM_OID_H
#define CUSTOM_OID_H
#include "custom_utils.h"

//oid.h

/** OID is not found. */
#define CUSTOM_ERR_OID_NOT_FOUND                         -0x002E
/** output buffer is too small */
#define CUSTOM_ERR_OID_BUF_TOO_SMALL                     -0x000B

/* This is for the benefit of X.509, but defined here in order to avoid
 * having a "backwards" include of x.509.h here */
/*
 * X.509 extension types (internal, arbitrary values for bitsets)
 */
#define CUSTOM_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER    (1 << 0)
#define CUSTOM_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER      (1 << 1)
#define CUSTOM_OID_X509_EXT_KEY_USAGE                   (1 << 2)
#define CUSTOM_OID_X509_EXT_CERTIFICATE_POLICIES        (1 << 3)
#define CUSTOM_OID_X509_EXT_POLICY_MAPPINGS             (1 << 4)
#define CUSTOM_OID_X509_EXT_SUBJECT_ALT_NAME            (1 << 5)
#define CUSTOM_OID_X509_EXT_ISSUER_ALT_NAME             (1 << 6)
#define CUSTOM_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS     (1 << 7)
#define CUSTOM_OID_X509_EXT_BASIC_CONSTRAINTS           (1 << 8)
#define CUSTOM_OID_X509_EXT_NAME_CONSTRAINTS            (1 << 9)
#define CUSTOM_OID_X509_EXT_POLICY_CONSTRAINTS          (1 << 10)
#define CUSTOM_OID_X509_EXT_EXTENDED_KEY_USAGE          (1 << 11)
#define CUSTOM_OID_X509_EXT_CRL_DISTRIBUTION_POINTS     (1 << 12)
#define CUSTOM_OID_X509_EXT_INIHIBIT_ANYPOLICY          (1 << 13)
#define CUSTOM_OID_X509_EXT_FRESHEST_CRL                (1 << 14)
#define CUSTOM_OID_X509_EXT_NS_CERT_TYPE                (1 << 16)
#define CUSTOM_OID_X509_EXT_NONCE                       (1 << 24) // new_impl  
#define CUSTOM_OID_X509_EXT_DICE_CERTS                  (1 << 25) // new_impl
#define CUSTOM_OID_X509_EXT_ATTESTATION_PROOF           (1 << 26) // new_impl

/*
 * Top level OID tuples
 */
#define CUSTOM_OID_ISO_MEMBER_BODIES           "\x2a"          /* {iso(1) member-body(2)} */
#define CUSTOM_OID_ISO_IDENTIFIED_ORG          "\x2b"          /* {iso(1) identified-organization(3)} */
#define CUSTOM_OID_ISO_CCITT_DS                "\x55"          /* {joint-iso-ccitt(2) ds(5)} */
#define CUSTOM_OID_ISO_ITU_COUNTRY             "\x60"          /* {joint-iso-itu-t(2) country(16)} */

/*
 * ISO Member bodies OID parts
 */
#define CUSTOM_OID_COUNTRY_US                  "\x86\x48"      /* {us(840)} */
#define CUSTOM_OID_ORG_RSA_DATA_SECURITY       "\x86\xf7\x0d"  /* {rsadsi(113549)} */
#define CUSTOM_OID_RSA_COMPANY                 CUSTOM_OID_ISO_MEMBER_BODIES CUSTOM_OID_COUNTRY_US \
        CUSTOM_OID_ORG_RSA_DATA_SECURITY                                 /* {iso(1) member-body(2) us(840) rsadsi(113549)} */
#define CUSTOM_OID_ORG_ANSI_X9_62              "\xce\x3d" /* ansi-X9-62(10045) */
#define CUSTOM_OID_ANSI_X9_62                  CUSTOM_OID_ISO_MEMBER_BODIES CUSTOM_OID_COUNTRY_US \
        CUSTOM_OID_ORG_ANSI_X9_62

/*
 * ISO Identified organization OID parts
 */
#define CUSTOM_OID_ORG_DOD                     "\x06"          /* {dod(6)} */
#define CUSTOM_OID_ORG_OIW                     "\x0e"
#define CUSTOM_OID_OIW_SECSIG                  CUSTOM_OID_ORG_OIW "\x03"
#define CUSTOM_OID_OIW_SECSIG_ALG              CUSTOM_OID_OIW_SECSIG "\x02"
#define CUSTOM_OID_OIW_SECSIG_SHA1             CUSTOM_OID_OIW_SECSIG_ALG "\x1a"
#define CUSTOM_OID_ORG_CERTICOM                "\x81\x04"  /* certicom(132) */
#define CUSTOM_OID_CERTICOM                    CUSTOM_OID_ISO_IDENTIFIED_ORG \
        CUSTOM_OID_ORG_CERTICOM
#define CUSTOM_OID_ORG_TELETRUST               "\x24" /* teletrust(36) */
#define CUSTOM_OID_TELETRUST                   CUSTOM_OID_ISO_IDENTIFIED_ORG \
        CUSTOM_OID_ORG_TELETRUST

/*
 * ISO ITU OID parts
 */
#define CUSTOM_OID_ORGANIZATION                "\x01"          /* {organization(1)} */
#define CUSTOM_OID_ISO_ITU_US_ORG              CUSTOM_OID_ISO_ITU_COUNTRY CUSTOM_OID_COUNTRY_US \
        CUSTOM_OID_ORGANIZATION                                                                                            /* {joint-iso-itu-t(2) country(16) us(840) organization(1)} */

#define CUSTOM_OID_ORG_GOV                     "\x65"          /* {gov(101)} */
#define CUSTOM_OID_GOV                         CUSTOM_OID_ISO_ITU_US_ORG CUSTOM_OID_ORG_GOV /* {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)} */

#define CUSTOM_OID_ORG_NETSCAPE                "\x86\xF8\x42"  /* {netscape(113730)} */
#define CUSTOM_OID_NETSCAPE                    CUSTOM_OID_ISO_ITU_US_ORG CUSTOM_OID_ORG_NETSCAPE /* Netscape OID {joint-iso-itu-t(2) country(16) us(840) organization(1) netscape(113730)} */

/* ISO arc for standard certificate and CRL extensions */
#define CUSTOM_OID_ID_CE                       CUSTOM_OID_ISO_CCITT_DS "\x1D" /**< id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29} */

#define CUSTOM_OID_NIST_ALG                    CUSTOM_OID_GOV "\x03\x04" /** { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) */

/**
 * Private Internet Extensions
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *                      security(5) mechanisms(5) pkix(7) }
 */
#define CUSTOM_OID_INTERNET                    CUSTOM_OID_ISO_IDENTIFIED_ORG CUSTOM_OID_ORG_DOD \
    "\x01"
#define CUSTOM_OID_PKIX                        CUSTOM_OID_INTERNET "\x05\x05\x07"

/*
 * Arc for standard naming attributes
 */
#define CUSTOM_OID_AT                          CUSTOM_OID_ISO_CCITT_DS "\x04" /**< id-at OBJECT IDENTIFIER ::= {joint-iso-ccitt(2) ds(5) 4} */
#define CUSTOM_OID_AT_CN                       CUSTOM_OID_AT "\x03" /**< id-at-commonName AttributeType:= {id-at 3} */
#define CUSTOM_OID_AT_SUR_NAME                 CUSTOM_OID_AT "\x04" /**< id-at-surName AttributeType:= {id-at 4} */
#define CUSTOM_OID_AT_SERIAL_NUMBER            CUSTOM_OID_AT "\x05" /**< id-at-serialNumber AttributeType:= {id-at 5} */
#define CUSTOM_OID_AT_COUNTRY                  CUSTOM_OID_AT "\x06" /**< id-at-countryName AttributeType:= {id-at 6} */
#define CUSTOM_OID_AT_LOCALITY                 CUSTOM_OID_AT "\x07" /**< id-at-locality AttributeType:= {id-at 7} */
#define CUSTOM_OID_AT_STATE                    CUSTOM_OID_AT "\x08" /**< id-at-state AttributeType:= {id-at 8} */
#define CUSTOM_OID_AT_ORGANIZATION             CUSTOM_OID_AT "\x0A" /**< id-at-organizationName AttributeType:= {id-at 10} */
#define CUSTOM_OID_AT_ORG_UNIT                 CUSTOM_OID_AT "\x0B" /**< id-at-organizationalUnitName AttributeType:= {id-at 11} */
#define CUSTOM_OID_AT_TITLE                    CUSTOM_OID_AT "\x0C" /**< id-at-title AttributeType:= {id-at 12} */
#define CUSTOM_OID_AT_POSTAL_ADDRESS           CUSTOM_OID_AT "\x10" /**< id-at-postalAddress AttributeType:= {id-at 16} */
#define CUSTOM_OID_AT_POSTAL_CODE              CUSTOM_OID_AT "\x11" /**< id-at-postalCode AttributeType:= {id-at 17} */
#define CUSTOM_OID_AT_GIVEN_NAME               CUSTOM_OID_AT "\x2A" /**< id-at-givenName AttributeType:= {id-at 42} */
#define CUSTOM_OID_AT_INITIALS                 CUSTOM_OID_AT "\x2B" /**< id-at-initials AttributeType:= {id-at 43} */
#define CUSTOM_OID_AT_GENERATION_QUALIFIER     CUSTOM_OID_AT "\x2C" /**< id-at-generationQualifier AttributeType:= {id-at 44} */
#define CUSTOM_OID_AT_UNIQUE_IDENTIFIER        CUSTOM_OID_AT "\x2D" /**< id-at-uniqueIdentifier AttributeType:= {id-at 45} */
#define CUSTOM_OID_AT_DN_QUALIFIER             CUSTOM_OID_AT "\x2E" /**< id-at-dnQualifier AttributeType:= {id-at 46} */
#define CUSTOM_OID_AT_PSEUDONYM                CUSTOM_OID_AT "\x41" /**< id-at-pseudonym AttributeType:= {id-at 65} */

#define CUSTOM_OID_UID                         "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01" /** id-domainComponent AttributeType:= {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) uid(1)} */
#define CUSTOM_OID_DOMAIN_COMPONENT            "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19" /** id-domainComponent AttributeType:= {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) domainComponent(25)} */

/*
 * OIDs for standard certificate extensions
 */
#define CUSTOM_OID_AUTHORITY_KEY_IDENTIFIER    CUSTOM_OID_ID_CE "\x23" /**< id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 } */
#define CUSTOM_OID_SUBJECT_KEY_IDENTIFIER      CUSTOM_OID_ID_CE "\x0E" /**< id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 } */
#define CUSTOM_OID_KEY_USAGE                   CUSTOM_OID_ID_CE "\x0F" /**< id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 } */
#define CUSTOM_OID_CERTIFICATE_POLICIES        CUSTOM_OID_ID_CE "\x20" /**< id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 } */
#define CUSTOM_OID_POLICY_MAPPINGS             CUSTOM_OID_ID_CE "\x21" /**< id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 } */
#define CUSTOM_OID_SUBJECT_ALT_NAME            CUSTOM_OID_ID_CE "\x11" /**< id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 } */
#define CUSTOM_OID_ISSUER_ALT_NAME             CUSTOM_OID_ID_CE "\x12" /**< id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 } */
#define CUSTOM_OID_SUBJECT_DIRECTORY_ATTRS     CUSTOM_OID_ID_CE "\x09" /**< id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 } */
#define CUSTOM_OID_BASIC_CONSTRAINTS           CUSTOM_OID_ID_CE "\x13" /**< id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 } */
#define CUSTOM_OID_NAME_CONSTRAINTS            CUSTOM_OID_ID_CE "\x1E" /**< id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 } */
#define CUSTOM_OID_POLICY_CONSTRAINTS          CUSTOM_OID_ID_CE "\x24" /**< id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 } */
#define CUSTOM_OID_EXTENDED_KEY_USAGE          CUSTOM_OID_ID_CE "\x25" /**< id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 } */
#define CUSTOM_OID_CRL_DISTRIBUTION_POINTS     CUSTOM_OID_ID_CE "\x1F" /**< id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 } */
#define CUSTOM_OID_INIHIBIT_ANYPOLICY          CUSTOM_OID_ID_CE "\x36" /**< id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 } */
#define CUSTOM_OID_FRESHEST_CRL                CUSTOM_OID_ID_CE "\x2E" /**< id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 } */

/*
 * Certificate policies
 */
#define CUSTOM_OID_ANY_POLICY              CUSTOM_OID_CERTIFICATE_POLICIES "\x00" /**< anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 } */

/*
 * Netscape certificate extensions
 */
#define CUSTOM_OID_NS_CERT                 CUSTOM_OID_NETSCAPE "\x01"
#define CUSTOM_OID_NS_CERT_TYPE            CUSTOM_OID_NS_CERT  "\x01"
#define CUSTOM_OID_NS_BASE_URL             CUSTOM_OID_NS_CERT  "\x02"
#define CUSTOM_OID_NS_REVOCATION_URL       CUSTOM_OID_NS_CERT  "\x03"
#define CUSTOM_OID_NS_CA_REVOCATION_URL    CUSTOM_OID_NS_CERT  "\x04"
#define CUSTOM_OID_NS_RENEWAL_URL          CUSTOM_OID_NS_CERT  "\x07"
#define CUSTOM_OID_NS_CA_POLICY_URL        CUSTOM_OID_NS_CERT  "\x08"
#define CUSTOM_OID_NS_SSL_SERVER_NAME      CUSTOM_OID_NS_CERT  "\x0C"
#define CUSTOM_OID_NS_COMMENT              CUSTOM_OID_NS_CERT  "\x0D"
#define CUSTOM_OID_NS_DATA_TYPE            CUSTOM_OID_NETSCAPE "\x02"
#define CUSTOM_OID_NS_CERT_SEQUENCE        CUSTOM_OID_NS_DATA_TYPE "\x05"

/*
 * OIDs for CRL extensions
 */
#define CUSTOM_OID_PRIVATE_KEY_USAGE_PERIOD    CUSTOM_OID_ID_CE "\x10"
#define CUSTOM_OID_CRL_NUMBER                  CUSTOM_OID_ID_CE "\x14" /**< id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 } */

/*
 * X.509 v3 Extended key usage OIDs
 */
#define CUSTOM_OID_ANY_EXTENDED_KEY_USAGE      CUSTOM_OID_EXTENDED_KEY_USAGE "\x00" /**< anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 } */

#define CUSTOM_OID_KP                          CUSTOM_OID_PKIX "\x03" /**< id-kp OBJECT IDENTIFIER ::= { id-pkix 3 } */
#define CUSTOM_OID_SERVER_AUTH                 CUSTOM_OID_KP "\x01" /**< id-kp-serverAuth OBJECT IDENTIFIER ::= { id-kp 1 } */
#define CUSTOM_OID_CLIENT_AUTH                 CUSTOM_OID_KP "\x02" /**< id-kp-clientAuth OBJECT IDENTIFIER ::= { id-kp 2 } */
#define CUSTOM_OID_CODE_SIGNING                CUSTOM_OID_KP "\x03" /**< id-kp-codeSigning OBJECT IDENTIFIER ::= { id-kp 3 } */
#define CUSTOM_OID_EMAIL_PROTECTION            CUSTOM_OID_KP "\x04" /**< id-kp-emailProtection OBJECT IDENTIFIER ::= { id-kp 4 } */
#define CUSTOM_OID_TIME_STAMPING               CUSTOM_OID_KP "\x08" /**< id-kp-timeStamping OBJECT IDENTIFIER ::= { id-kp 8 } */
#define CUSTOM_OID_OCSP_SIGNING                CUSTOM_OID_KP "\x09" /**< id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 } */

/**
 * Wi-SUN Alliance Field Area Network
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *                      private(4) enterprise(1) WiSUN(45605) FieldAreaNetwork(1) }
 */
#define CUSTOM_OID_WISUN_FAN                   CUSTOM_OID_INTERNET "\x04\x01\x82\xe4\x25\x01"

#define CUSTOM_OID_ON                          CUSTOM_OID_PKIX "\x08" /**< id-on OBJECT IDENTIFIER ::= { id-pkix 8 } */
#define CUSTOM_OID_ON_HW_MODULE_NAME           CUSTOM_OID_ON "\x04" /**< id-on-hardwareModuleName OBJECT IDENTIFIER ::= { id-on 4 } */

/*
 * PKCS definition OIDs
 */

#define CUSTOM_OID_PKCS                CUSTOM_OID_RSA_COMPANY "\x01" /**< pkcs OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) 1 } */
#define CUSTOM_OID_PKCS1               CUSTOM_OID_PKCS "\x01" /**< pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 } */
#define CUSTOM_OID_PKCS5               CUSTOM_OID_PKCS "\x05" /**< pkcs-5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 } */
#define CUSTOM_OID_PKCS7               CUSTOM_OID_PKCS "\x07" /**< pkcs-7 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 } */
#define CUSTOM_OID_PKCS9               CUSTOM_OID_PKCS "\x09" /**< pkcs-9 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 } */
#define CUSTOM_OID_PKCS12              CUSTOM_OID_PKCS "\x0c" /**< pkcs-12 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 } */

/*
 * PKCS#1 OIDs
 */
#define CUSTOM_OID_PKCS1_RSA           CUSTOM_OID_PKCS1 "\x01" /**< rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 } */
#define CUSTOM_OID_PKCS1_MD5           CUSTOM_OID_PKCS1 "\x04" /**< md5WithRSAEncryption ::= { pkcs-1 4 } */
#define CUSTOM_OID_PKCS1_SHA1          CUSTOM_OID_PKCS1 "\x05" /**< sha1WithRSAEncryption ::= { pkcs-1 5 } */
#define CUSTOM_OID_PKCS1_SHA224        CUSTOM_OID_PKCS1 "\x0e" /**< sha224WithRSAEncryption ::= { pkcs-1 14 } */
#define CUSTOM_OID_PKCS1_SHA256        CUSTOM_OID_PKCS1 "\x0b" /**< sha256WithRSAEncryption ::= { pkcs-1 11 } */
#define CUSTOM_OID_PKCS1_SHA384        CUSTOM_OID_PKCS1 "\x0c" /**< sha384WithRSAEncryption ::= { pkcs-1 12 } */
#define CUSTOM_OID_PKCS1_SHA512        CUSTOM_OID_PKCS1 "\x0d" /**< sha512WithRSAEncryption ::= { pkcs-1 13 } */

#define CUSTOM_OID_RSA_SHA_OBS         "\x2B\x0E\x03\x02\x1D"

#define CUSTOM_OID_PKCS9_EMAIL         CUSTOM_OID_PKCS9 "\x01" /**< emailAddress AttributeType ::= { pkcs-9 1 } */

/* RFC 4055 */
#define CUSTOM_OID_RSASSA_PSS          CUSTOM_OID_PKCS1 "\x0a" /**< id-RSASSA-PSS ::= { pkcs-1 10 } */
#define CUSTOM_OID_MGF1                CUSTOM_OID_PKCS1 "\x08" /**< id-mgf1 ::= { pkcs-1 8 } */

/*
 * Digest algorithms
 */
#define CUSTOM_OID_DIGEST_ALG_MD5              CUSTOM_OID_RSA_COMPANY "\x02\x05" /**< id-custom_md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 } */
#define CUSTOM_OID_DIGEST_ALG_SHA1             CUSTOM_OID_ISO_IDENTIFIED_ORG \
        CUSTOM_OID_OIW_SECSIG_SHA1                                                                        /**< id-custom_sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 } */
#define CUSTOM_OID_DIGEST_ALG_SHA224           CUSTOM_OID_NIST_ALG "\x02\x04" /**< id-sha224 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 4 } */
#define CUSTOM_OID_DIGEST_ALG_SHA256           CUSTOM_OID_NIST_ALG "\x02\x01" /**< id-custom_sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1 } */

#define CUSTOM_OID_DIGEST_ALG_SHA384           CUSTOM_OID_NIST_ALG "\x02\x02" /**< id-sha384 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2 } */

#define CUSTOM_OID_DIGEST_ALG_SHA512           CUSTOM_OID_NIST_ALG "\x02\x03" /**< id-custom_sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3 } */

#define CUSTOM_OID_DIGEST_ALG_RIPEMD160        CUSTOM_OID_TELETRUST "\x03\x02\x01" /**< id-ripemd160 OBJECT IDENTIFIER :: { iso(1) identified-organization(3) teletrust(36) algorithm(3) hashAlgorithm(2) ripemd160(1) } */

#define CUSTOM_OID_HMAC_SHA1                   CUSTOM_OID_RSA_COMPANY "\x02\x07" /**< id-hmacWithSHA1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 7 } */

#define CUSTOM_OID_HMAC_SHA224                 CUSTOM_OID_RSA_COMPANY "\x02\x08" /**< id-hmacWithSHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 8 } */

#define CUSTOM_OID_HMAC_SHA256                 CUSTOM_OID_RSA_COMPANY "\x02\x09" /**< id-hmacWithSHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 9 } */

#define CUSTOM_OID_HMAC_SHA384                 CUSTOM_OID_RSA_COMPANY "\x02\x0A" /**< id-hmacWithSHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 10 } */

#define CUSTOM_OID_HMAC_SHA512                 CUSTOM_OID_RSA_COMPANY "\x02\x0B" /**< id-hmacWithSHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 11 } */

/*
 * Encryption algorithms
 */
#define CUSTOM_OID_DES_CBC                     CUSTOM_OID_ISO_IDENTIFIED_ORG \
        CUSTOM_OID_OIW_SECSIG_ALG "\x07"                                                                        /**< desCBC OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 7 } */
#define CUSTOM_OID_DES_EDE3_CBC                CUSTOM_OID_RSA_COMPANY "\x03\x07" /**< des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) -- us(840) rsadsi(113549) encryptionAlgorithm(3) 7 } */
#define CUSTOM_OID_AES                         CUSTOM_OID_NIST_ALG "\x01" /** aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 1 } */

/*
 * Key Wrapping algorithms
 */
/*
 * RFC 5649
 */
#define CUSTOM_OID_AES128_KW                   CUSTOM_OID_AES "\x05" /** id-aes128-wrap     OBJECT IDENTIFIER ::= { aes 5 } */
#define CUSTOM_OID_AES128_KWP                  CUSTOM_OID_AES "\x08" /** id-aes128-wrap-pad OBJECT IDENTIFIER ::= { aes 8 } */
#define CUSTOM_OID_AES192_KW                   CUSTOM_OID_AES "\x19" /** id-aes192-wrap     OBJECT IDENTIFIER ::= { aes 25 } */
#define CUSTOM_OID_AES192_KWP                  CUSTOM_OID_AES "\x1c" /** id-aes192-wrap-pad OBJECT IDENTIFIER ::= { aes 28 } */
#define CUSTOM_OID_AES256_KW                   CUSTOM_OID_AES "\x2d" /** id-aes256-wrap     OBJECT IDENTIFIER ::= { aes 45 } */
#define CUSTOM_OID_AES256_KWP                  CUSTOM_OID_AES "\x30" /** id-aes256-wrap-pad OBJECT IDENTIFIER ::= { aes 48 } */
/*
 * PKCS#5 OIDs
 */
#define CUSTOM_OID_PKCS5_PBKDF2                CUSTOM_OID_PKCS5 "\x0c" /**< id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12} */
#define CUSTOM_OID_PKCS5_PBES2                 CUSTOM_OID_PKCS5 "\x0d" /**< id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13} */
#define CUSTOM_OID_PKCS5_PBMAC1                CUSTOM_OID_PKCS5 "\x0e" /**< id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14} */

/*
 * PKCS#5 PBES1 algorithms
 */
#define CUSTOM_OID_PKCS5_PBE_MD5_DES_CBC       CUSTOM_OID_PKCS5 "\x03" /**< pbeWithMD5AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 3} */
#define CUSTOM_OID_PKCS5_PBE_MD5_RC2_CBC       CUSTOM_OID_PKCS5 "\x06" /**< pbeWithMD5AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 6} */
#define CUSTOM_OID_PKCS5_PBE_SHA1_DES_CBC      CUSTOM_OID_PKCS5 "\x0a" /**< pbeWithSHA1AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 10} */
#define CUSTOM_OID_PKCS5_PBE_SHA1_RC2_CBC      CUSTOM_OID_PKCS5 "\x0b" /**< pbeWithSHA1AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 11} */

/*
 * PKCS#7 OIDs
 */
#define CUSTOM_OID_PKCS7_DATA                        CUSTOM_OID_PKCS7 "\x01" /**< Content type is Data OBJECT IDENTIFIER ::= {pkcs-7 1} */
#define CUSTOM_OID_PKCS7_SIGNED_DATA                 CUSTOM_OID_PKCS7 "\x02" /**< Content type is Signed Data OBJECT IDENTIFIER ::= {pkcs-7 2} */
#define CUSTOM_OID_PKCS7_ENVELOPED_DATA              CUSTOM_OID_PKCS7 "\x03" /**< Content type is Enveloped Data OBJECT IDENTIFIER ::= {pkcs-7 3} */
#define CUSTOM_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA   CUSTOM_OID_PKCS7 "\x04" /**< Content type is Signed and Enveloped Data OBJECT IDENTIFIER ::= {pkcs-7 4} */
#define CUSTOM_OID_PKCS7_DIGESTED_DATA               CUSTOM_OID_PKCS7 "\x05" /**< Content type is Digested Data OBJECT IDENTIFIER ::= {pkcs-7 5} */
#define CUSTOM_OID_PKCS7_ENCRYPTED_DATA              CUSTOM_OID_PKCS7 "\x06" /**< Content type is Encrypted Data OBJECT IDENTIFIER ::= {pkcs-7 6} */

/*
 * PKCS#8 OIDs
 */
#define CUSTOM_OID_PKCS9_CSR_EXT_REQ           CUSTOM_OID_PKCS9 "\x0e" /**< extensionRequest OBJECT IDENTIFIER ::= {pkcs-9 14} */

/*
 * PKCS#12 PBE OIDs
 */
#define CUSTOM_OID_PKCS12_PBE                      CUSTOM_OID_PKCS12 "\x01" /**< pkcs-12PbeIds OBJECT IDENTIFIER ::= {pkcs-12 1} */

#define CUSTOM_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC    CUSTOM_OID_PKCS12_PBE "\x03" /**< pbeWithSHAAnd3-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 3} */
#define CUSTOM_OID_PKCS12_PBE_SHA1_DES2_EDE_CBC    CUSTOM_OID_PKCS12_PBE "\x04" /**< pbeWithSHAAnd2-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 4} */
#define CUSTOM_OID_PKCS12_PBE_SHA1_RC2_128_CBC     CUSTOM_OID_PKCS12_PBE "\x05" /**< pbeWithSHAAnd128BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 5} */
#define CUSTOM_OID_PKCS12_PBE_SHA1_RC2_40_CBC      CUSTOM_OID_PKCS12_PBE "\x06" /**< pbeWithSHAAnd40BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 6} */

/*
 * EC key algorithms from RFC 5480
 */

/* id-ecPublicKey OBJECT IDENTIFIER ::= {
 *       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 } */
#define CUSTOM_OID_EC_ALG_UNRESTRICTED         CUSTOM_OID_ANSI_X9_62 "\x02\01"

/*   id-ecDH OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) certicom(132)
 *     schemes(1) ecdh(12) } */
#define CUSTOM_OID_EC_ALG_ECDH                 CUSTOM_OID_CERTICOM "\x01\x0c"

/*
 * ECParameters namedCurve identifiers, from RFC 5480, RFC 5639, and SEC2
 */

/* secp192r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 } */
#define CUSTOM_OID_EC_GRP_SECP192R1        CUSTOM_OID_ANSI_X9_62 "\x03\x01\x01"

/* secp224r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 33 } */
#define CUSTOM_OID_EC_GRP_SECP224R1        CUSTOM_OID_CERTICOM "\x00\x21"

/* secp256r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 } */
#define CUSTOM_OID_EC_GRP_SECP256R1        CUSTOM_OID_ANSI_X9_62 "\x03\x01\x07"

/* secp384r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 34 } */
#define CUSTOM_OID_EC_GRP_SECP384R1        CUSTOM_OID_CERTICOM "\x00\x22"

/* secp521r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 35 } */
#define CUSTOM_OID_EC_GRP_SECP521R1        CUSTOM_OID_CERTICOM "\x00\x23"

/* secp192k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 31 } */
#define CUSTOM_OID_EC_GRP_SECP192K1        CUSTOM_OID_CERTICOM "\x00\x1f"

/* secp224k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 32 } */
#define CUSTOM_OID_EC_GRP_SECP224K1        CUSTOM_OID_CERTICOM "\x00\x20"

/* secp256k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 10 } */
#define CUSTOM_OID_EC_GRP_SECP256K1        CUSTOM_OID_CERTICOM "\x00\x0a"

/* RFC 5639 4.1
 * ecStdCurvesAndGeneration OBJECT IDENTIFIER::= {iso(1)
 * identified-organization(3) teletrust(36) algorithm(3) signature-
 * algorithm(3) ecSign(2) 8}
 * ellipticCurve OBJECT IDENTIFIER ::= {ecStdCurvesAndGeneration 1}
 * versionOne OBJECT IDENTIFIER ::= {ellipticCurve 1} */
#define CUSTOM_OID_EC_BRAINPOOL_V1         CUSTOM_OID_TELETRUST "\x03\x03\x02\x08\x01\x01"

/* brainpoolP256r1 OBJECT IDENTIFIER ::= {versionOne 7} */
#define CUSTOM_OID_EC_GRP_BP256R1          CUSTOM_OID_EC_BRAINPOOL_V1 "\x07"

/* brainpoolP384r1 OBJECT IDENTIFIER ::= {versionOne 11} */
#define CUSTOM_OID_EC_GRP_BP384R1          CUSTOM_OID_EC_BRAINPOOL_V1 "\x0B"

/* brainpoolP512r1 OBJECT IDENTIFIER ::= {versionOne 13} */
#define CUSTOM_OID_EC_GRP_BP512R1          CUSTOM_OID_EC_BRAINPOOL_V1 "\x0D"

/*
 * SEC1 C.1
 *
 * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
 * id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1)}
 */
#define CUSTOM_OID_ANSI_X9_62_FIELD_TYPE   CUSTOM_OID_ANSI_X9_62 "\x01"
#define CUSTOM_OID_ANSI_X9_62_PRIME_FIELD  CUSTOM_OID_ANSI_X9_62_FIELD_TYPE "\x01"

/*
 * ECDSA signature identifiers, from RFC 5480
 */
#define CUSTOM_OID_ANSI_X9_62_SIG          CUSTOM_OID_ANSI_X9_62 "\x04" /* signatures(4) */
#define CUSTOM_OID_ANSI_X9_62_SIG_SHA2     CUSTOM_OID_ANSI_X9_62_SIG "\x03" /* ecdsa-with-SHA2(3) */

/* ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) 1 } */
#define CUSTOM_OID_ECDSA_SHA1              CUSTOM_OID_ANSI_X9_62_SIG "\x01"

/* ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 1 } */
#define CUSTOM_OID_ECDSA_SHA224            CUSTOM_OID_ANSI_X9_62_SIG_SHA2 "\x01"

/* ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 2 } */
#define CUSTOM_OID_ECDSA_SHA256            CUSTOM_OID_ANSI_X9_62_SIG_SHA2 "\x02"

/* ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 3 } */
#define CUSTOM_OID_ECDSA_SHA384            CUSTOM_OID_ANSI_X9_62_SIG_SHA2 "\x03"

/* ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 4 } */
#define CUSTOM_OID_ECDSA_SHA512            CUSTOM_OID_ANSI_X9_62_SIG_SHA2 "\x04"

/**
 * \brief Base OID descriptor structure
 */
typedef struct custom_oid_descriptor_t {
    const char *CUSTOM_PRIVATE(asn1);               /*!< OID ASN.1 representation       */
    size_t CUSTOM_PRIVATE(asn1_len);                /*!< length of asn1                 */
    const char *CUSTOM_PRIVATE(name);               /*!< official name (e.g. from RFC)  */
    const char *CUSTOM_PRIVATE(description);        /*!< human friendly description     */
} custom_oid_descriptor_t;

// custom new_impl
#define CUSTOM_OID_NONCE               "\x2b\x65\x60"
#define CUSTOM_OID_DICE_CERTS          "\x2b\x65\x61"
#define CUSTOM_OID_ATTESTATION_PROOF   "\x2b\x65\x62"

#endif /* oid.h */
