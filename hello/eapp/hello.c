#include <stdio.h>
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/md5.h"

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
  return 0;
}
