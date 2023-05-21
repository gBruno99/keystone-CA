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

void print_mbedtls_x509_cert(char *name, mbedtls_x509_crt crt);

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

  // Test my_mbedtls
  int ret;
  mbedtls_x509write_cert cert_root;
  mbedtls_x509write_crt_init(&cert_root);

  // Setting the name of the issuer of the cert
  
  ret = mbedtls_x509write_crt_set_issuer_name(&cert_root, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name(&cert_root, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_test;
  mbedtls_pk_init(&subj_key_test);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_test;
  mbedtls_pk_init(&issu_key_test);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_secret_key, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key_test, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_root[] = {0xFF, 0xFF, 0xFF};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_root, MBEDTLS_MD_KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20220101000000", "20230101000000");
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der_root[1024];
  int effe_len_cert_der_root;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_root, cert_der_root, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_root = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_root = cert_der_root;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_root = 1024-effe_len_cert_der_root;
  // cert_real points to the starts of the cert in der format
  cert_real_root += dif_root;

  mbedtls_pk_free(&issu_key_test);
  mbedtls_pk_free(&subj_key_test);
  mbedtls_x509write_crt_free(&cert_root);
  print_hex_string("Cert generated", cert_real_root, effe_len_cert_der_root);


  mbedtls_x509_crt cert_sm_p, cert_root_p, cert_man_p;
  mbedtls_x509_crt_init(&cert_sm_p);
  mbedtls_x509_crt_init(&cert_root_p);
  mbedtls_x509_crt_init(&cert_man_p);
  ret = mbedtls_x509_crt_parse_der(&cert_sm_p, certs[0], sizes[0]);
  my_printf("Parsing cert_sm - ret: %d\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_root_p, certs[1], sizes[1]);
  my_printf("Parsing cert_root - ret: %d\n", ret);
  ret = mbedtls_x509_crt_parse_der(&cert_man_p, certs[2], sizes[2]);
  my_printf("Parsing cert_man - ret: %d\n", ret);
  my_printf("\n");
  print_mbedtls_x509_cert("cert_sm", cert_sm_p);
  print_mbedtls_x509_cert("cert_root", cert_root_p);
  print_mbedtls_x509_cert("cert_man", cert_man_p);
  mbedtls_x509_crt_free(&cert_sm_p);
  mbedtls_x509_crt_free(&cert_root_p);
  mbedtls_x509_crt_free(&cert_man_p);

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}

int print_mbedtls_asn1_buf(char *name, mbedtls_asn1_buf buf){
  my_printf("%s_tag: %02x\n", name, buf.tag);
  print_hex_string(name, buf.p, buf.len);
  return 0;
}

int print_mbedtls_asn1_named_data(char *name, mbedtls_asn1_named_data buf){
  char tmp[128] = {0};
  sprintf(tmp, "%s_oid", name);
  print_mbedtls_asn1_buf(tmp, buf.oid);
  sprintf(tmp, "%s_val", name);
  print_mbedtls_asn1_buf(name, buf.val);
  my_printf("%s_next: %p\n", name, buf.next);
  return 0;
}

int print_mbedtls_x509_time(char *name, mbedtls_x509_time tm){
  my_printf("%s:\n- year=%d, mon=%d, day=%d\n- hour=%d, min=%d, sec=%d\n",
    name, tm.year, tm.mon, tm.day, tm.hour, tm.min, tm.sec);
  return 0;
}

int print_mbedtls_pk_context(char *name, mbedtls_pk_context pk){
  char tmp[128] = {0};
  sprintf(tmp, "%s - pk", name);
  my_printf("%s: %s\n", name, pk.pk_info->name);
  print_hex_string(tmp, mbedtls_pk_ed25519(pk)->pub_key, PUBLIC_KEY_SIZE);
  return 0;
}

void print_mbedtls_x509_cert(char *name, mbedtls_x509_crt crt){
  my_printf("%s:\n", name);
  print_mbedtls_asn1_buf("raw", crt.raw);
  print_mbedtls_asn1_buf("tbs", crt.tbs);
  my_printf("\n");
  my_printf("version: %d\n", crt.version);
  print_mbedtls_asn1_buf("serial", crt.serial);
  print_mbedtls_asn1_buf("sig_oid", crt.sig_oid);
  my_printf("\n");
  print_mbedtls_asn1_buf("issuer_raw", crt.issuer_raw);
  print_mbedtls_asn1_buf("subject_raw", crt.subject_raw);
  my_printf("\n");
  print_mbedtls_asn1_named_data("issuer", crt.issuer);
  print_mbedtls_asn1_named_data("subject", crt.subject);
  my_printf("\n");
  print_mbedtls_x509_time("valid_from", crt.valid_from);
  print_mbedtls_x509_time("valid_to", crt.valid_to);
  my_printf("\n");
  print_mbedtls_asn1_buf("pk_raw", crt.pk_raw);
  print_mbedtls_pk_context("pk", crt.pk);
  my_printf("\n");
  print_mbedtls_asn1_buf("issuer_id", crt.issuer_id);
  print_mbedtls_asn1_buf("subject_id", crt.subject_id);
  print_mbedtls_asn1_buf("v3_ext", crt.v3_ext);
  my_printf("\n");
  print_mbedtls_asn1_buf("hash", crt.hash);
  my_printf("\n");
  print_mbedtls_asn1_buf("sig", crt.sig);
  my_printf("sig_md: %d\n", crt.sig_md);
  my_printf("sig_pk: %d\n", crt.sig_pk);
  my_printf("\n\n");
  return;
}
