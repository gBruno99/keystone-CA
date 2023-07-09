#include <stdio.h>
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/md5.h"
#include "openssl/ssl.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"

int main()
{
  printf("hello, world!\n");
  mbedtls_printf("Mbedtls test\n");
  int i, ret;
  unsigned char digest[16];
  char str[] = "Hello, world!";

  mbedtls_printf("\n  MD5('%s') = ", str);

  if ((ret = mbedtls_md5((unsigned char *) str, 13, digest)) != 0) {
      mbedtls_exit(MBEDTLS_EXIT_FAILURE);
  }

  for (i = 0; i < 16; i++) {
      mbedtls_printf("%02x", digest[i]);
  }

  mbedtls_printf("\n\n");

  mbedtls_asn1_buf test = {MBEDTLS_ASN1_OCTET_STRING, 4, (unsigned char *)"test"};
  unsigned char buf[10] = {0};
  unsigned char *p = buf + 9;
  ret = mbedtls_asn1_write_raw_buffer(&p, buf, test.p, (size_t) test.len);
  mbedtls_printf("asn1 write raw buffer: %d, %s\n", ret, p);
  unsigned char buf2[20] = {0};
  p = buf2 + 9;
  ret = mbedtls_asn1_write_len(&p, buf2, 4);
  mbedtls_printf("asn1 write len: %d, %02x\n", ret,(int) *(p));
  size_t len;
  ret = mbedtls_asn1_get_len(&p, buf2+15, &len);
  mbedtls_printf("asn1 get len: %d, %lu\n", ret, len);
  mbedtls_printf("\n");


  // Test OpenSSL
  SSL_CONF_CTX *cctx = NULL;
  cctx = SSL_CONF_CTX_new();
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE);
  printf("Test OpenSSL\n");

  return 0;
}
