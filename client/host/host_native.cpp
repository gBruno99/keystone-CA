//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <edge_call.h>
#include <keystone.h>

extern "C"{
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/md5.h"
}

unsigned long
print_string(char* str);
void
print_string_wrapper(void* buffer);
unsigned long
send_LDevID_csr(void);
void
send_LDevID_csr_wrapper(void* buffer);
#define OCALL_PRINT_STRING 1
#define OCALL_SEND_LDEVID_CSR 9

/***
 * An example call that will be exposed to the enclave application as
 * an "ocall". This is performed by an edge_wrapper function (below,
 * print_string_wrapper) and by registering that wrapper with the
 * enclave object (below, main).
 ***/
unsigned long
print_string(char* str) {
  return printf("Enclave said: \"%s\"\n", str);
}

int
main(int argc, char** argv) {
  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(1024 * 1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024 * 1024);

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_SEND_LDEVID_CSR, send_LDevID_csr_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  mbedtls_printf("Mbedtls test - host\n");
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
  fflush(stdout);
  enclave.run();

  return 0;
}

/***
 * Example edge-wrapper function. These are currently hand-written
 * wrappers, but will have autogeneration tools in the future.
 ***/
void
print_string_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  /* Pass the arguments from the eapp to the exported ocall function */
  ret_val = print_string((char*)call_args);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

unsigned long
send_LDevID_csr(void){
  return printf("Sending CSR...\n");
}

void
send_LDevID_csr_wrapper(void* buffer){
  // printf("Entering into wrapper\n");
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  // printf("Before sending\n");
  ret_val = send_LDevID_csr();
  
   /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  // printf("Returning\n");
  /* This will now eventually return control to the enclave */
  return;
}
