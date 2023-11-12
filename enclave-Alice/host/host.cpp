//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "net.h"
#include "crt.h"

using namespace Keystone;

#define OCALL_NET_CONNECT 1
#define OCALL_NET_SEND    2
#define OCALL_NET_RECV    3
#define OCALL_NET_FREE    4
#define OCALL_NET_BIND    5
#define OCALL_NET_ACCEPT  6
#define OCALL_STORE_CRT   7
#define OCALL_READ_CRT    8

int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  params.setFreeMemSize(1024 * 1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024 * 1024);
  params.setUUID((unsigned char*) "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  register_call(OCALL_NET_CONNECT, net_connect_wrapper);
  register_call(OCALL_NET_SEND, net_send_wrapper);
  register_call(OCALL_NET_RECV, net_recv_wrapper);
  register_call(OCALL_NET_BIND, net_bind_wrapper);
  register_call(OCALL_NET_ACCEPT, net_accept_wrapper);
  register_call(OCALL_NET_FREE, net_free_wrapper);
  register_call(OCALL_STORE_CRT, store_cert_wrapper);
  register_call(OCALL_READ_CRT, read_cert_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  enclave.run();

  return 0;
}
