//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"

// #include "mbedtls/build_info.h"
// #include "mbedtls/platform.h"
// #include "mbedtls/md5.h"

#include "app/malloc.h"

#include "printf.h"

#define OCALL_PRINT_STRING 1

unsigned long ocall_print_string(char* string);

int my_printf(const char* format, ...);
// int my_fprintf(FILE *stream, const char *format, ...);
void my_exit(int status);
void setup_mbedtls_functions(void);

typedef struct test_s {
    int a;
    long b;
    char c;
} test;

/*
int main(){
  setup_mbedtls_functions();

  mbedtls_printf("Mbedtls test\n");
  mbedtls_fprintf(0, "Mbedtls test fprintf: %d\n", 15);
  int i, ret, len;
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

  
  i = 10;
  ocall_print_string("Hello World");
  len = my_printf("test print in print.h: %d\n", i);
  my_printf("len = %d\n", len);
  my_printf("strlen = %d\n", strlen("test print in print.h: 10\n"));

  my_printf("Testing calloc and free...\n");
  test* v1 = calloc(1,sizeof(test));
  my_printf("Returned pointer: %p\n", v1);
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->a = 15;
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->b = 18U;
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->c = 'A';
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);

  test* v2 = calloc(1,sizeof(test));
  my_printf("Returned pointer: %p\n", v2);
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->a = 16;
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->b = 19U;
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->c = 'A';
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);

  free(v1);
  free(v2);

  gen_LDevID_kp();
  cert_LDevID_kp();

  EAPP_RETURN(0);
}
*/

int main(){
  int i = 10, len;
  ocall_print_string("Hello World");
  len = my_printf("test print in print.h: %d\n", i);
  my_printf("len = %d\n", len);
  my_printf("strlen = %d\n", strlen("test print in print.h: 10\n"));

  my_printf("Testing calloc and free...\n");
  test* v1 = calloc(1,sizeof(test));
  my_printf("Returned pointer: %p\n", v1);
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->a = 15;
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->b = 18U;
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);
  v1->c = 'A';
  my_printf("v1->a: %d, v1->b: %li, v1->c: %c\n", v1->a, v1->b, v1->c);

  test* v2 = calloc(1,sizeof(test));
  my_printf("Returned pointer: %p\n", v2);
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->a = 16;
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->b = 19U;
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);
  v2->c = 'A';
  my_printf("v2->a: %d, v2->b: %li, v2->c: %c\n", v2->a, v2->b, v2->c);

  free(v1);
  free(v2);

  gen_LDevID_kp();
  cert_LDevID_kp();

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}

int my_printf(const char* format, ...){
  int len;
  va_list va;
  va_start(va, format);
  char buffer[512];
  len = vsnprintf(buffer, 512, format, va);
  rt_print_string(buffer, len+1);
  va_end(va);
  return len;
}

/*
// stream -> stdout
int my_fprintf(FILE *stream, const char *format, ...){
  (void) stream;
  int len;
  va_list va;
  va_start(va, format);
  char buffer[512];
  len = vsnprintf(buffer, 512, format, va);
  rt_print_string(buffer, len+1);
  va_end(va);
  return len;
}
*/
void my_exit(int status){
    EAPP_RETURN(status);
}
/*
void setup_mbedtls_functions(void){
  my_printf("Setting exit...\n");
  mbedtls_platform_set_exit(my_exit);
  my_printf("Setting printf...\n");
  mbedtls_platform_set_printf(my_printf);
  my_printf("Setting snprintf...\n");
  mbedtls_platform_set_snprintf(snprintf);
  my_printf("Setting calloc and free...\n");
  mbedtls_platform_set_calloc_free(calloc, free);
  my_printf("Setting fprintf...\n");
  mbedtls_platform_set_fprintf(my_fprintf);
  return;
}
*/