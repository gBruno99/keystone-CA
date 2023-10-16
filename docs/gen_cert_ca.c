/*** Code to generate CA cert ***/
/*
static const unsigned char seed[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3, 
  0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46, 0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};
*/
/*
    int ret;
    unsigned char sanctum_ca_private_key[PRIVATE_KEY_SIZE];
    unsigned char sanctum_ca_public_key[PUBLIC_KEY_SIZE];
    mbedtls_x509write_cert cert_ca;
    mbedtls_x509write_crt_init(&cert_ca);

    // Setting the name of the issuer of the cert

    ed25519_create_keypair(sanctum_ca_public_key, sanctum_ca_private_key, seed);

    print_hex_string("CA-SK", (unsigned char *)sanctum_ca_private_key, PRIVATE_KEY_SIZE);
    print_hex_string("CA-PK", (unsigned char *)sanctum_ca_public_key, PUBLIC_KEY_SIZE);

    ret = mbedtls_x509write_crt_set_issuer_name(&cert_ca, "O=Certificate Authority");
    if (ret != 0)
    {
        return 0;
    }

    // Setting the name of the subject of the cert

    ret = mbedtls_x509write_crt_set_subject_name(&cert_ca, "O=Certificate Authority");
    if (ret != 0)
    {
        return 0;
    }

    // pk context used to embed the keys of the subject of the cert
    mbedtls_pk_context subj_key_ca;
    mbedtls_pk_init(&subj_key_ca);

    // pk context used to embed the keys of the issuer of the cert
    mbedtls_pk_context issu_key_ca;
    mbedtls_pk_init(&issu_key_ca);

    // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
    ret = mbedtls_pk_parse_ed25519_key(&issu_key_ca, sanctum_ca_private_key, PRIVATE_KEY_SIZE, PARSE_PRIVATE_KEY);
    if (ret != 0)
    {
        return 0;
    }

    ret = mbedtls_pk_parse_ed25519_key(&issu_key_ca, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
    if (ret != 0)
    {
        return 0;
    }

    // Parsing the public key of the security monitor that will be inserted in its certificate
    ret = mbedtls_pk_parse_ed25519_key(&subj_key_ca, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
    if (ret != 0)
    {
        return 0;
    }

    // Variable  used to specify the serial of the cert
    unsigned char serial_ca[] = {0x0F, 0x0F, 0x0F};

    // The public key of the security monitor is inserted in the structure
    mbedtls_x509write_crt_set_subject_key(&cert_ca, &subj_key_ca);

    // The private key of the embedded CA is used later to sign the cert
    mbedtls_x509write_crt_set_issuer_key(&cert_ca, &issu_key_ca);

    // The serial of the cert is setted
    mbedtls_x509write_crt_set_serial_raw(&cert_ca, serial_ca, 3);

    // The algoithm used to do the hash for the signature is specified
    mbedtls_x509write_crt_set_md_alg(&cert_ca, MBEDTLS_MD_KEYSTONE_SHA3);

    // The validity of the crt is specified
    ret = mbedtls_x509write_crt_set_validity(&cert_ca, "20230101000000", "20240101000000");
    if (ret != 0)
    {
        return 0;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints(&cert_ca, 1, 10);
    if (ret != 0)
    {
        return 0;
    }

    unsigned char cert_der_ca[1024];
    int effe_len_cert_der_ca;

    // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
    ret = mbedtls_x509write_crt_der(&cert_ca, cert_der_ca, 1024, NULL, NULL); //, test, &len);
    if (ret != 0)
    {
        effe_len_cert_der_ca = ret;
    }
    else
    {
        return 0;
    }

    unsigned char *cert_real_ca = cert_der_ca;
    // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
    int dif_ca = 1024 - effe_len_cert_der_ca;
    // cert_real points to the starts of the cert in der format
    cert_real_ca += dif_ca;

    mbedtls_pk_free(&issu_key_ca);
    mbedtls_pk_free(&subj_key_ca);
    mbedtls_x509write_crt_free(&cert_ca);
    print_hex_string("Cert generated", cert_real_ca, effe_len_cert_der_ca);
*/