//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
//#include <stdio.h>
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"

//#include "mbedtls/build_info.h"
//#include "mbedtls/platform.h"
//#include "mbedtls/md5.h"

#include "app/malloc.h"

#include "printf.h"

#define OCALL_PRINT_STRING 1

unsigned long ocall_print_string(char* string);
/*
void *my_calloc(size_t nelem, size_t elsize){
    (void)nelem;
    (void)elsize;
    return NULL;
}
void my_free(void *ptr){
    (void)ptr;
    return;
}
*/
int my_printf(const char* format, ...);

void my_exit(int status){
    EAPP_RETURN(status);
}

typedef struct test_s {
    int a;
    long b;
    char c;
} test;

int main(){
    /*
  my_printf("Setting exit...\n");
  mbedtls_platform_set_exit(my_exit);
  my_printf("Setting printf...\n");
  mbedtls_platform_set_printf(my_printf);
  my_printf("Setting snprintf...\n");
  mbedtls_platform_set_snprintf(snprintf);
  my_printf("Setting calloc and free...\n");
  mbedtls_platform_set_calloc_free(calloc, free);
  
  mbedtls_printf("Mbedtls test\n");
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
  */
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

#define MY_MEM_SIZE 8192 // 8 KB of freemem
#define MAX_CALLOC 128

unsigned char  my_mem[MY_MEM_SIZE] = {0};
unsigned char* allocated_pointers[MAX_CALLOC];
unsigned long allocated_size[MAX_CALLOC];
unsigned int num_alloc = 0;

unsigned char* aligned_pointer(unsigned char* pointer, size_t elsize){
    unsigned long diff = ((unsigned long)pointer % elsize);
    if(diff == 0)
        return pointer;
    return pointer + (elsize - diff);
}

/*
void *my_calloc(size_t nelem, size_t elsize){
    unsigned char *head = my_mem;
    unsigned long size = nelem*elsize;
    int i;
    my_printf("head: %p\n", head);
    if(num_alloc == MAX_CALLOC)
        return NULL;

    for(i = 0; i < num_alloc; i++){
        if((allocated_pointers[i]-aligned_pointer(head,elsize)) >= size)
            break;
        head = allocated_pointers[i] + allocated_size[i];
    }

    if(((i == 0) || (i == num_alloc)) && ((my_mem+MY_MEM_SIZE-aligned_pointer(head, elsize)) < size))
        return NULL;

    for(int j = num_alloc-1; j >= i; j--){
        allocated_pointers[j+1] = allocated_pointers[j];
        allocated_size[j+1] = allocated_size[j];
    }
    my_printf("i: %d\n", i);
    allocated_pointers[i] = aligned_pointer(head, elsize);
    allocated_size[i] = size;
    num_alloc++;

    return (void*) allocated_pointers[i];
}

void my_free(void *ptr){
    int i;
    unsigned char* head = (unsigned char *) ptr;

    if((unsigned char *)ptr < my_mem || (unsigned char *)ptr >= my_mem+MY_MEM_SIZE)
        return;
    for(i = 0; i < num_alloc; i++){
        if(allocated_pointers[i] == head)
            break;
    }
    if(i == num_alloc)
        return;
    
    while(head != (head+allocated_size[i])){
        *head = 0;
        head++;
    }

    for(int j=i; j<num_alloc-1; j++){
        allocated_pointers[j] = allocated_pointers[j+1];
        allocated_size[j] = allocated_size[j+1];
    }

    num_alloc--;

    return;
}
*/

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