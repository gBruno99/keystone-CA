//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"
#include "printf.h"
#include "custom_functions.h"

#define OCALL_PRINT_STRING 1
#define PUBLIC_KEY_SIZE 32

static const unsigned char sanctum_dev_secret_key[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57, 0x6a, 0x9a, 0xb6,
  0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29, 0x85, 0x2f, 0xb9, 0x60,
  0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89, 0xec, 0x06, 0xa8, 0x72, 0x34,
  0x51, 0xaa, 0x0e, 0x4a
};

static const unsigned char sanctum_dev_public_key[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96,
  0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46,
  0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};

unsigned long ocall_print_string(char* string);


int main(){

  unsigned char pk[PUBLIC_KEY_SIZE] = {0};
  ocall_print_string("Hello World");
  create_keypair(pk, 15);

  print_hex_string("PK", pk, PUBLIC_KEY_SIZE);

  unsigned char *certs[3];
  certs[0] = mbedtls_calloc(1, 1024);
  if(certs[0]==NULL)
    EAPP_RETURN(-1);
  certs[1] = mbedtls_calloc(1, 1024);
  if(certs[1]==NULL){
    mbedtls_free(certs[0]);
    EAPP_RETURN(-1);
  }
  certs[2] = mbedtls_calloc(1, 1024);
  if(certs[2]==NULL){
    mbedtls_free(certs[0]);
    mbedtls_free(certs[1]);
    EAPP_RETURN(-1);
  }

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

  // Test my_mbedtls
  int ret;
  mbedtls_x509write_cert cert_man;
  mbedtls_x509write_crt_init(&cert_man);

  // Setting the name of the issuer of the cert
  
  ret = mbedtls_x509write_crt_set_issuer_name(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_man;
  mbedtls_pk_init(&subj_key_man);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_man;
  mbedtls_pk_init(&issu_key_man);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_man, sanctum_dev_secret_key, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_man, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key_man, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_man[] = {0xFF, 0xFF, 0xFF};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_man, &subj_key_man);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_man, &issu_key_man);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_man, serial_man, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_man, MBEDTLS_MD_KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_man, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_x509write_crt_set_basic_constraints(&cert_man, 1, 10);
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der_man[1024];
  int effe_len_cert_der_man;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_man, cert_der_man, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_man = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_man = cert_der_man;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_man = 1024-effe_len_cert_der_man;
  // cert_real points to the starts of the cert in der format
  cert_real_man += dif_man;

  mbedtls_pk_free(&issu_key_man);
  mbedtls_pk_free(&subj_key_man);
  mbedtls_x509write_crt_free(&cert_man);
  print_hex_string("Cert generated", cert_real_man, effe_len_cert_der_man);


  mbedtls_x509_crt cert_chain;
  mbedtls_x509_crt_init(&cert_chain);
  ret = mbedtls_x509_crt_parse_der(&cert_chain, certs[0], sizes[0]);
  my_printf("Parsing cert_sm - ret: %d\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_chain, certs[1], sizes[1]);
  my_printf("Parsing cert_root - ret: %d\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_chain, certs[2], sizes[2]);
  my_printf("Parsing cert_man - ret: %d\n", ret);
  my_printf("\n");
  print_mbedtls_x509_cert("cert_sm", cert_chain);

  // cert_chain.hash.p[15] = 0x56;

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9

  print_mbedtls_x509_cert("cert_root", *(cert_chain.next));
  // cert_chain.next->ca_istrue = 1;
  print_mbedtls_x509_cert("cert_man", *(*(cert_chain.next)).next);
  // (cert_chain.next)->next->ca_istrue = 1;


  mbedtls_x509_crt trusted_certs;
  mbedtls_x509_crt_init(&trusted_certs);
  ret = mbedtls_x509_crt_parse_der(&trusted_certs, cert_real_man, effe_len_cert_der_man);
  my_printf("Parsing trusted cert - ret: %d\n", ret);
  my_printf("\n");
  print_mbedtls_x509_cert("trusted_cert", trusted_certs);
  // trusted_certs.ca_istrue = 1;

  uint32_t flags = 0;
  ret = mbedtls_x509_crt_verify(&cert_chain, &trusted_certs, NULL, NULL, &flags, NULL, NULL);
  my_printf("Verifing cert chain - ret: %u, flags = %u\n", ret, flags);
  my_printf("\n");

  mbedtls_x509_crt_free(&cert_chain);
  mbedtls_x509_crt_free(&trusted_certs);

  ret = 1;
  mbedtls_pk_context key;
  char buf[1024];
  mbedtls_x509write_csr req;
  unsigned char key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT | MBEDTLS_X509_KU_DATA_ENCIPHERMENT | MBEDTLS_X509_KU_KEY_AGREEMENT;
  const char subject_name[] = "CN=Client,O=Enclave";
  unsigned char nonce[] = {
    0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23,
    0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3
  }; 

  mbedtls_x509write_csr_init(&req);
  mbedtls_pk_init(&key);
  my_memset(buf, 0, sizeof(buf));

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_KEYSTONE_SHA3);

  ret = mbedtls_x509write_csr_set_key_usage(&req, key_usage);
  my_printf("Setting key usage - ret: %d\n", ret);

  ret = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
  my_printf("Setting key usage - ret: %d\n", ret);
  
  ret = mbedtls_pk_parse_public_key(&key, pk, PUBLIC_KEY_SIZE, 0);
  my_printf("Setting pk context - ret: %d\n", ret);

  mbedtls_x509write_csr_set_key(&req, &key);
  my_printf("Setting pk\n");

  /*
  unsigned char test[64] = {0};
  unsigned char *c = test+64;

  ret = mbedtls_asn1_write_named_bitstring(&c, test, nonce, NONCE_LEN*8);
  print_hex_string("Test", test, 64);
  
  my_printf("int: %d\n", sizeof(int));
  */

  ret = mbedtls_x509write_csr_set_nonce(&req, nonce);
  my_printf("Setting nonce - ret: %d\n", ret);

  crypto_interface(1, nonce, NONCE_LEN, outbuf, &outbuf_len, pk);
  print_hex_string("attest_proof", outbuf, outbuf_len);

  ret = mbedtls_x509write_csr_set_attestation_proof(&req, outbuf);
  my_printf("Setting attestation proof - ret: %d\n", ret);

  ret = mbedtls_x509write_csr_set_dice_certs(&req, (unsigned char **)certs, sizes);
  my_printf("Setting chain of certs - ret: %d\n", ret);

  print_mbedtls_x509write_csr("CSR write struct", &req);

  unsigned char out_csr[3072];
  int csr_len;

  csr_len = mbedtls_x509write_csr_der(&req, out_csr, 3072, NULL, NULL);
  my_printf("Writing csr - ret: %d\n", csr_len);

  unsigned char *parsed_csr = out_csr;
  int dif_csr = 3072-csr_len;
  parsed_csr += dif_csr;

  print_hex_string("CSR", parsed_csr, csr_len);

  mbedtls_pk_free(&key);
  mbedtls_x509write_csr_free(&req);

  mbedtls_free(certs[0]);
  mbedtls_free(certs[1]);
  mbedtls_free(certs[2]);

  mbedtls_x509_csr csr;
  mbedtls_x509_csr_init(&csr);

  ret = mbedtls_x509_csr_parse_der(&csr, parsed_csr, csr_len);
  my_printf("Parsing csr - ret: %d\n", ret);

  print_mbedtls_x509_csr("Parsed CSR", csr);

  mbedtls_x509_csr_free(&csr);

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}

