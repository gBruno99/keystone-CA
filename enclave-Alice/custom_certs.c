#include "custom_certs.h"

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
"MIICJDCCAYOgAwIBAgIBATAMBggqhkjOPQQDAgUAMC4xDDAKBgNVBAMMA1ZlcjER\r\n" \
"MA8GA1UECgwIVmVyaWZpZXIxCzAJBgNVBAYTAklUMB4XDTIzMDEwMTAwMDAwMFoX\r\n" \
"DTI0MDEwMTAwMDAwMFowLjEMMAoGA1UEAwwDVmVyMREwDwYDVQQKDAhWZXJpZmll\r\n" \
"cjELMAkGA1UEBhMCSVQwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHjdXiAfteX\r\n" \
"se9QA6zQiMLZSpY7vHQaw3bvYA3d0kmpgUVxZF/kzhLtsJPVb3yZgGvbTWSaXNqB\r\n" \
"GnyOxo/bj6EMCQGmEleZiakh2k97TfkNKblZSs4+KWTboKDp7AOECV66sOfXkvdv\r\n" \
"TG4v2NWEg/S/DJCrNBPmo7tQegUTkAt1EQVqR6NNMEswCQYDVR0TBAIwADAdBgNV\r\n" \
"HQ4EFgQUU+mlbmN9mEaMIUudPCFMsJ7PvtwwHwYDVR0jBBgwFoAUU+mlbmN9mEaM\r\n" \
"IUudPCFMsJ7PvtwwDAYIKoZIzj0EAwIFAAOBjAAwgYgCQgFlN+TEmWHEz2aK5EDW\r\n" \
"V7NshThBRy8dvTGFcwP680HAh3YQt1n5AoqnsCkxf/qgj92h1Uby5KulZcondkvT\r\n" \
"vnGr+AJCAXuvHe/RvDNSh1SU3s/hOPojwx2IVqo5gJoShb3tjO9gwp68ZKboHUgc\r\n" \
"ggwMyqnCUworuCdtvtcWBSSp+tXVdund\r\n" \
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

const unsigned char ref_cert_man[] = {
  0x30, 0x81, 0xfb, 0x30, 0x81, 0xac, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x00, 0xff, 0xff, 
  0xff, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 
  0x72, 0x65, 0x72, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
  0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 
  0x30, 0x30, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 
  0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72, 0x30, 0x2c, 0x30, 0x07, 
  0x06, 0x03, 0x7b, 0x30, 0x78, 0x05, 0x00, 0x03, 0x21, 0x00, 0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17,
  0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 
  0x2b, 0x46, 0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 
  0x01, 0x0a, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x41, 0x00, 0xb1, 0xef,
  0xe8, 0xeb, 0x43, 0xd9, 0x2e, 0x9f, 0x05, 0x00, 0xcb, 0x63, 0xc3, 0x33, 0x80, 0x0f, 0x8a, 0x1e, 
  0x6c, 0x7b, 0x13, 0x4c, 0x64, 0x10, 0xfb, 0xc6, 0x48, 0xe4, 0x00, 0x9b, 0xc4, 0xf3, 0xdf, 0x12, 
  0xab, 0x69, 0x79, 0x19, 0x5f, 0xb6, 0x02, 0x30, 0x40, 0x38, 0x13, 0xa0, 0x42, 0x59, 0xe2, 0x5a, 
  0x3e, 0x13, 0x8e, 0x9d, 0xa1, 0x10, 0x42, 0x93, 0x0f, 0x58, 0xcd, 0x07, 0xfc, 0x06
};

const int ref_cert_man_len = 254;

const char alice_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICPTCCAZygAwIBAgIBATAMBggqhkjOPQQDAgUAMDkxCzAJBgNVBAMMAkNBMR0w\r\n" \
"GwYDVQQKDBRDZXJ0aWZpY2F0ZUF1dGhvcml0eTELMAkGA1UEBhMCSVQwHhcNMjMw\r\n" \
"MTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjA8MQ4wDAYDVQQDDAVBbGljZTEdMBsG\r\n" \
"A1UECgwUQ2VydGlmaWNhdGVBdXRob3JpdHkxCzAJBgNVBAYTAklUMIGbMBAGByqG\r\n" \
"SM49AgEGBSuBBAAjA4GGAAQAMKybeZwjM+jNgxSJoE/nyzvIrO6EtPDWSt4qOSX2\r\n" \
"nJtyIz6SteZeKmaSncLjdU6AukQ5tC2eigPaWE2Wuii1kxIBJWgHyGhWnyYoUXqS\r\n" \
"1Wkd+gDDJMr+rwG7gSbdrUm7dK6IXyosmyi56ZXTgSklsnqaCvY9EMncXEgb/9OP\r\n" \
"0RmKyhWjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFA1tapC5yCvraBJAxa+4CC2m\r\n" \
"czOGMB8GA1UdIwQYMBaAFN9R6F+/WOrcT/pySdzr0DMVsIgYMAwGCCqGSM49BAMC\r\n" \
"BQADgYwAMIGIAkIBKMou7t4Llyi0vClL24qUqtj532eZx5ii1+sjIC+duNIDNIvE\r\n" \
"gLP1GEfVfq3l5bgGVzMbAEqq5vPn2jgHhPyJMfYCQgET6HK0eMVKLPpeV2Tz3e6R\r\n" \
"EeLqr2Ge1OITrhmhYwUeqmWAFLF1g1TOAqLEBT1bas5i9b5aGfwDFm1q284EJble\r\n" \
"hA==\r\n" \
"-----END CERTIFICATE-----\r\n";

const unsigned long alice_cert_pem_len = sizeof(alice_cert_pem);

const char alice_key_pem[] = 
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MIHcAgEBBEIAXHnHfJBUeeEipFCqIiRLIbJB4ZYhDvR9sDI5hd2SVXoBFjK4KIfz\r\n" \
"sj0MWOe11yD0adMS3m66EqOp7h73Lzek82CgBwYFK4EEACOhgYkDgYYABAAwrJt5\r\n" \
"nCMz6M2DFImgT+fLO8is7oS08NZK3io5Jfacm3IjPpK15l4qZpKdwuN1ToC6RDm0\r\n" \
"LZ6KA9pYTZa6KLWTEgElaAfIaFafJihRepLVaR36AMMkyv6vAbuBJt2tSbt0rohf\r\n" \
"KiybKLnpldOBKSWyepoK9j0QydxcSBv/04/RGYrKFQ==\r\n" \
"-----END EC PRIVATE KEY-----\r\n";

const unsigned long alice_key_pem_len = sizeof(alice_key_pem);

const char bob_cert_pem[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICOzCCAZqgAwIBAgIBATAMBggqhkjOPQQDAgUAMDkxCzAJBgNVBAMMAkNBMR0w\r\n" \
"GwYDVQQKDBRDZXJ0aWZpY2F0ZUF1dGhvcml0eTELMAkGA1UEBhMCSVQwHhcNMjMw\r\n" \
"MTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjA6MQwwCgYDVQQDDANCb2IxHTAbBgNV\r\n" \
"BAoMFENlcnRpZmljYXRlQXV0aG9yaXR5MQswCQYDVQQGEwJJVDCBmzAQBgcqhkjO\r\n" \
"PQIBBgUrgQQAIwOBhgAEAYOQu/rcYisMOFUNlaIklGlk4V9jaGiijCOhYm285hvw\r\n" \
"veTwX3AlDomFQ5heggENJUHxrH/zrXHvcdiBEmNzyI2bANcunGPgwz1U0k6nswiB\r\n" \
"VapZ8sgmyNIt4IWZnJLpXRrQSG9Wy4zC8r7ASFdlgbtV5wOybwCIVD6yCPlu2fRD\r\n" \
"GfLmo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBTD9X7IYpo4xYebLgOmNg+I0fdV\r\n" \
"KDAfBgNVHSMEGDAWgBTfUehfv1jq3E/6cknc69AzFbCIGDAMBggqhkjOPQQDAgUA\r\n" \
"A4GMADCBiAJCAMZ9eDdq6JjKmldkSOW4Bz5aJchupI8/z7ot85Lb/+f+Ak2ihYqf\r\n" \
"E6ggqcrTmqPq9SJ5NCKyRhgGme9WUZi9wS05AkIAl/NW9Tgqqy8hgRA0X+gFO0+M\r\n" \
"aBI3dLvBIRBmY/LFzO/dvCNiIjSIALXE4IR/QChzNBqFLS8FbpOQilCC9AtSFcw=\r\n" \
"-----END CERTIFICATE-----\r\n";

const unsigned long bob_cert_pem_len = sizeof(bob_cert_pem);

const char bob_key_pem[] = 
"-----BEGIN EC PRIVATE KEY-----\r\n" \
"MIHcAgEBBEIBj1dfgce2yrcxy6+xx0M6GkJvEHmRn9cfJ/eVngBQq2yZ8a5p4hjJ\r\n" \
"sPFX5ojcs74S8CarbUeEfR/6lO6AsPDbtaCgBwYFK4EEACOhgYkDgYYABAGDkLv6\r\n" \
"3GIrDDhVDZWiJJRpZOFfY2hooowjoWJtvOYb8L3k8F9wJQ6JhUOYXoIBDSVB8ax/\r\n" \
"861x73HYgRJjc8iNmwDXLpxj4MM9VNJOp7MIgVWqWfLIJsjSLeCFmZyS6V0a0Ehv\r\n" \
"VsuMwvK+wEhXZYG7VecDsm8AiFQ+sgj5btn0Qxny5g==\r\n" \
"-----END EC PRIVATE KEY-----\r\n";

const unsigned long bob_key_pem_len = sizeof(bob_key_pem);
