//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"
#include "printf.h"

#define OCALL_PRINT_STRING 1
#define PUBLIC_KEY_SIZE 32

unsigned long ocall_print_string(char* string);

int my_printf(const char* format, ...);

int print_hex_string(char* name, unsigned char* value, int size);

int main(){

  unsigned char pk[PUBLIC_KEY_SIZE] = {0};
  ocall_print_string("Hello World");
  create_keypair(pk, 15);

  print_hex_string("PK", pk, PUBLIC_KEY_SIZE);

  unsigned char certs[3][1024];
  int sizes[3];
  get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);

  print_hex_string("cert_1", certs[0], sizes[0]);
  print_hex_string("cert_2", certs[1], sizes[1]);
  print_hex_string("cert_3", certs[2], sizes[2]);

  unsigned char data[22] = "Test Crypto Interface\0";
  unsigned char outbuf[512];
  size_t outbuf_len;

  crypto_interface(2, data, sizeof(data), outbuf, &outbuf_len, pk);
  print_hex_string("outbuf", outbuf, outbuf_len);

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
  va_end(va);
  rt_print_string(buffer, len+1);
  return len;
}

int print_hex_string(char* name, unsigned char* value, int size){
  my_printf("%s: 0x", name);
  for(int i = 0; i< size; i++){
    my_printf("%02x", value[i]);
  }
  my_printf("\n");
  my_printf("%s_len: %d\n", name, size);
  my_printf("\n");
  return 0;
}