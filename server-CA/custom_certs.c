/*
Generating CA keypair: ./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=ca_key.key
Genrating CA certificate: ./programs/x509/cert_write selfsign=1 issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=1 max_pathlen=10 output_file=ca.crt
*/

const char ca_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"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\r\n"  \
"QMpPIe8Pig==\r\n"                                                      \
"-----END CERTIFICATE-----\r\n";

const unsigned long ca_cert_pem_len = sizeof(ca_cert_pem);

const char ca_key_pem[] = 
"-----BEGIN RSA PRIVATE KEY-----\r\n"                                   \
"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\r\n"      \
"-----END RSA PRIVATE KEY-----\r\n";

const unsigned long ca_key_pem_len = sizeof(ca_key_pem);
