/*
Generating CA keypair: ./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=ca_key.key
Genrating CA certificate: ./programs/x509/cert_write selfsign=1 issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=1 max_pathlen=10 output_file=ca.crt
*/

const char ca_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICQzCCAaKgAwIBAgIBATAMBggqhkjOPQQDAgUAMDkxCzAJBgNVBAMMAkNBMR0w\r\n" \
"GwYDVQQKDBRDZXJ0aWZpY2F0ZUF1dGhvcml0eTELMAkGA1UEBhMCSVQwHhcNMjMw\r\n" \
"MTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjA5MQswCQYDVQQDDAJDQTEdMBsGA1UE\r\n" \
"CgwUQ2VydGlmaWNhdGVBdXRob3JpdHkxCzAJBgNVBAYTAklUMIGbMBAGByqGSM49\r\n" \
"AgEGBSuBBAAjA4GGAAQAi+1DqsygHgoztOKb2pPJlrS2mSmQdSILu4VBTBgGACtH\r\n" \
"LHqbt65wMnzej0HaQ4/aaPo2Coeop9Du7gVBBn8dX7cBv22S5lh+UeOBNMxS35JZ\r\n" \
"rYT7+WN37xkzsax4sTtX1uQhM26VPjlGa7VL3IXvMEdPY16rDumnj8IyZv/4t2Bl\r\n" \
"S2+jVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQowHQYDVR0OBBYEFN9R6F+/WOrcT/py\r\n" \
"Sdzr0DMVsIgYMB8GA1UdIwQYMBaAFN9R6F+/WOrcT/pySdzr0DMVsIgYMAwGCCqG\r\n" \
"SM49BAMCBQADgYwAMIGIAkIBptO7ojNAY8PMYFZ8fhsG3WFwtfV+FBup+0itLuxb\r\n" \
"awKkpXQE35Gd4Ls6HXM1UNeGlhSXWmE+g/dh0aDw28ZpKxcCQgCb4w480496uO/x\r\n" \
"nWyGCjZS0eaeH1b3Zexiip/9c0fhEHRFt/Kwk7g/GTpE4u/KbIg4M+0BqRBjPRjQ\r\n" \
"+aNvZ0MoeA==\r\n" \
"-----END CERTIFICATE-----\r\n";

const unsigned long ca_cert_pem_len = sizeof(ca_cert_pem);

const char ca_key_pem[] = 
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MIHcAgEBBEIAUnLZ8tnDXJtLlrM7r7YJ6QstqzpiSrYFKnMIxOgDuk0ZUWqpEpVW\r\n" \
"kWred12pGEvj6eENuKOmuwvwIt7l7I/8jfygBwYFK4EEACOhgYkDgYYABACL7UOq\r\n" \
"zKAeCjO04pvak8mWtLaZKZB1Igu7hUFMGAYAK0csepu3rnAyfN6PQdpDj9po+jYK\r\n" \
"h6in0O7uBUEGfx1ftwG/bZLmWH5R44E0zFLfklmthPv5Y3fvGTOxrHixO1fW5CEz\r\n" \
"bpU+OUZrtUvche8wR09jXqsO6aePwjJm//i3YGVLbw==\r\n" \
"-----END EC PRIVATE KEY-----\r\n";

const unsigned long ca_key_pem_len = sizeof(ca_key_pem);

const char ver_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICKzCCAYygAwIBAgIBATAMBggqhkjOPQQDAgUAMC4xDDAKBgNVBAMMA1ZlcjER\r\n" \
"MA8GA1UECgwIVmVyaWZpZXIxCzAJBgNVBAYTAklUMB4XDTIzMDEwMTAwMDAwMFoX\r\n" \
"DTI0MDEwMTAwMDAwMFowLjEMMAoGA1UEAwwDVmVyMREwDwYDVQQKDAhWZXJpZmll\r\n" \
"cjELMAkGA1UEBhMCSVQwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHjdXiAfteX\r\n" \
"se9QA6zQiMLZSpY7vHQaw3bvYA3d0kmpgUVxZF/kzhLtsJPVb3yZgGvbTWSaXNqB\r\n" \
"GnyOxo/bj6EMCQGmEleZiakh2k97TfkNKblZSs4+KWTboKDp7AOECV66sOfXkvdv\r\n" \
"TG4v2NWEg/S/DJCrNBPmo7tQegUTkAt1EQVqR6NWMFQwEgYDVR0TAQH/BAgwBgEB\r\n" \
"/wIBCjAdBgNVHQ4EFgQUU+mlbmN9mEaMIUudPCFMsJ7PvtwwHwYDVR0jBBgwFoAU\r\n" \
"U+mlbmN9mEaMIUudPCFMsJ7PvtwwDAYIKoZIzj0EAwIFAAOBigAwgYYCQVpY9rsv\r\n" \
"NE/xwiq1aurf6Wp0awFN7hbuKoZGttTpp78cEv4mihI500z75jCOe/iCWAlRu04Z\r\n" \
"iGRywn2YWlEuGR2WAkEsLh+maSH3yg7bXKt27fy34rLDGtSZ2/p8maNpft4b3Ho5\r\n" \
"GPk8xJNcfixlMH2hgm+qTvcwptUCybI5869Ej5ptGg==\r\n" \
"-----END CERTIFICATE-----\r\n";

const unsigned long ver_cert_pem_len = sizeof(ver_cert_pem);

const char ver_key_pem[] = 
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MIHcAgEBBEIBmT/mCY3KZQw2KWGxYJ7whwHliijzpcnjaPITcpebPO1RXKtkk2DK\r\n" \
"yh9RznxzPxZ3GsvprXciJWz0FptydRJglmmgBwYFK4EEACOhgYkDgYYABAHjdXiA\r\n" \
"fteXse9QA6zQiMLZSpY7vHQaw3bvYA3d0kmpgUVxZF/kzhLtsJPVb3yZgGvbTWSa\r\n" \
"XNqBGnyOxo/bj6EMCQGmEleZiakh2k97TfkNKblZSs4+KWTboKDp7AOECV66sOfX\r\n" \
"kvdvTG4v2NWEg/S/DJCrNBPmo7tQegUTkAt1EQVqRw==\r\n" \
"-----END EC PRIVATE KEY-----\r\n";

const unsigned long ver_key_pem_len = sizeof(ver_key_pem);
