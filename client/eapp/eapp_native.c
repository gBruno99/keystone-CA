//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <stdio.h>
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/md5.h"

#define OCALL_PRINT_STRING 1

unsigned long ocall_print_string(char* string);


int main(){

  printf("stdlib test - client\n");

  mbedtls_printf("MbedTLS Test - client\n");

  fflush(stdout);

  ocall_print_string("Hello World");

  gen_LDevID_kp();
  cert_LDevID_kp();
  // return 0;
  EAPP_RETURN(0);
}

/*
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
*/


unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}
