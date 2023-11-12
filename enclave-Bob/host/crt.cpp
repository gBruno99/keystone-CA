#include "edge/edge_call.h"
#include "host/keystone.h"
#include <stdio.h>
#include "crt.h"

#define CERT_FILENAME "/root/crt.crt"

void
store_cert_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  size_t ret;
  // printf("Opening...\n");
  FILE *fd = fopen(CERT_FILENAME, "w");
  if(fd == NULL){
    ret = -1;
    goto end_store_crt;
  }
  // printf("Writing 1...\n");
  ret = fwrite((void*) &arg_len, sizeof(size_t), 1, fd);
  if(ret != 1) {
    ret = -1;
    goto end_store_crt;
  }
  // printf("Writing 2...\n"); 
  ret = fwrite((void*) call_args, sizeof(unsigned char), arg_len, fd);
  if(ret != arg_len) {
    ret = -1;
    goto end_store_crt;
  }
  
end_store_crt:
  // printf("Closing...\n");
  if(fd != NULL) fclose(fd);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret, sizeof(size_t));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(size_t))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

void
read_cert_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  //int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  unsigned char tmp[1024+sizeof(size_t)] = {0};
  size_t crt_len = sizeof(size_t);
  size_t *ret_val = (size_t*) tmp;
  size_t ret;
  // printf("Opening...\n");
  FILE *fd = fopen(CERT_FILENAME, "r");
  if(fd == NULL) {
    ret = -1;
    goto end_read_crt;
  }
  // printf("Reading 1...\n");
  ret = fread((void*) &crt_len, sizeof(size_t), 1, fd);
  if(ret != 1) {
    ret = -1;
    goto end_read_crt;
  }
  // printf("Reading 2...\n"); 
  ret = fread((void*) tmp+sizeof(size_t), sizeof(unsigned char), crt_len, fd);
  if(ret != crt_len) {
    ret = -1;
    goto end_read_crt;
  }

end_read_crt:
  *ret_val = ret;
  // printf("Closing...\n");
  if(fd != NULL) fclose(fd);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, tmp, 1024+sizeof(size_t));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, 1024+sizeof(size_t))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}
