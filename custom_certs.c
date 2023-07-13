/*
Generating CA keypair: ./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=ca_key.key
Genrating CA certificate: ./programs/x509/cert_write selfsign=1 issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=1 max_pathlen=10 output_file=ca.crt
*/

unsigned char ca_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"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\r\n"  \
"yJuDUv6mGg==\r\n"                                                      \
"-----END CERTIFICATE-----\r\n";

unsigned char ca_key_pem[] = 
"-----BEGIN RSA PRIVATE KEY-----\r\n"                                   \
"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\r\n"      \
"-----END RSA PRIVATE KEY-----\r\n";