//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "string.h"
#include "edge/edge_call.h"
#include "app/syscall.h"
#include "app/malloc.h"
#include "printf.h"
//#include "custom_functions.h"
#include "ed25519/ed25519.h"
#include "sha3/sha3.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/platform.h"
#include "mbedtls/keystone_ext.h"
#include "mbedtls/print.h"

#define PUBLIC_KEY_SIZE     32
#define PRIVATE_KEY_SIZE    64
#define PARSE_PUBLIC_KEY    0
#define PARSE_PRIVATE_KEY   1
#define CERTS_MAX_LEN       512
#define CSR_SIZE            2048
#define HASH_LEN            64
#define SIG_LEN             64

#define PRINT_STRUCTS       0

static const unsigned char ref_cert_man[] = {
  0x30, 0x81, 0xfb, 0x30, 0x81, 0xac, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x00, 0xff, 0xff, 
  0xff, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 
  0x72, 0x65, 0x72, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
  0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 
  0x30, 0x30, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 
  0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72, 0x30, 0x2c, 0x30, 0x07, 
  0x06, 0x03, 0x7b, 0x30, 0x78, 0x05, 0x00, 0x03, 0x21, 0x00, 0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17,
  0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 
  0x2b, 0x46, 0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 
  0x01, 0x0a, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x41, 0x00, 0xb1, 0xef,
  0xe8, 0xeb, 0x43, 0xd9, 0x2e, 0x9f, 0x05, 0x00, 0xcb, 0x63, 0xc3, 0x33, 0x80, 0x0f, 0x8a, 0x1e, 
  0x6c, 0x7b, 0x13, 0x4c, 0x64, 0x10, 0xfb, 0xc6, 0x48, 0xe4, 0x00, 0x9b, 0xc4, 0xf3, 0xdf, 0x12, 
  0xab, 0x69, 0x79, 0x19, 0x5f, 0xb6, 0x02, 0x30, 0x40, 0x38, 0x13, 0xa0, 0x42, 0x59, 0xe2, 0x5a, 
  0x3e, 0x13, 0x8e, 0x9d, 0xa1, 0x10, 0x42, 0x93, 0x0f, 0x58, 0xcd, 0x07, 0xfc, 0x06
};

static const int ref_cert_man_len = 254;

static const unsigned char sanctum_ca_private_key[] = {
  0x60, 0x9e, 0x84, 0xdf, 0x9b, 0x49, 0x5d, 0xe7, 0xe1, 0xff, 0x76, 0x91, 0xa4, 0xb9, 0xff, 0xed, 
  0x56, 0x49, 0x0c, 0x4e, 0x51, 0x59, 0x4b, 0xa3, 0x7e, 0x85, 0xee, 0x91, 0x6e, 0x7a, 0x6e, 0x7a, 
  0x47, 0xdd, 0xd1, 0x4f, 0x9b, 0x31, 0x2b, 0x90, 0xaa, 0x4e, 0x12, 0x8a, 0x0d, 0xd7, 0xc3, 0x16, 
  0x25, 0xd7, 0x71, 0x41, 0xe4, 0x2d, 0xcb, 0x1e, 0x1b, 0xf8, 0x6a, 0x57, 0x7a, 0x54, 0x00, 0x76
};

static const unsigned char sanctum_ca_public_key[] = {
  0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23, 
  0x9b, 0xb4, 0x39, 0x31, 0x9d, 0x50, 0x47, 0xb1, 0xee, 0xe5, 0x62, 0xd9, 0xcc, 0x72, 0x6a, 0xc6
};

/*
static const unsigned char seed[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3, 
  0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46, 0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};

static const unsigned char sanctum_cert_ca[] = {
  0x30, 0x82, 0x01, 0x0c, 0x30, 0x81, 0xbd, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x0f, 0x0f, 
  0x0f, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x30, 0x20, 0x31, 0x1e, 0x30, 0x1c, 
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 
  0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 
  0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 
  0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x20, 0x31, 0x1e, 
  0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 
  0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x2c, 
  0x30, 0x07, 0x06, 0x03, 0x7b, 0x30, 0x78, 0x05, 0x00, 0x03, 0x21, 0x00, 0x95, 0xb2, 0xcd, 0xbd, 
  0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23, 0x9b, 0xb4, 0x39, 0x31, 
  0x9d, 0x50, 0x47, 0xb1, 0xee, 0xe5, 0x62, 0xd9, 0xcc, 0x72, 0x6a, 0xc6, 0xa3, 0x16, 0x30, 0x14, 
  0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 
  0xff, 0x02, 0x01, 0x0a, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x41, 0x00, 
  0x41, 0x79, 0x58, 0x40, 0x7f, 0xa8, 0xad, 0x8b, 0x36, 0xc9, 0x12, 0x2a, 0x77, 0x10, 0xde, 0x1c, 
  0x9a, 0xc2, 0x26, 0x8a, 0xb7, 0x79, 0xfe, 0x7f, 0xeb, 0x11, 0xfe, 0x6d, 0x97, 0xac, 0x4d, 0x56, 
  0x31, 0xaa, 0x24, 0x5a, 0x8d, 0xee, 0xca, 0x86, 0xef, 0x6e, 0x29, 0x56, 0x17, 0xd9, 0x24, 0xd7, 
  0x3d, 0x5f, 0x05, 0x98, 0x3a, 0xfe, 0x03, 0x03, 0x53, 0x95, 0xe3, 0x2a, 0x2b, 0x88, 0x30, 0x03
};
*/

#define MDSIZE 64
#define SIGNATURE_SIZE 64
#define ATTEST_DATA_MAXLEN 1024

typedef unsigned char byte;

struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

// static const int sanctum_cert_ca_len = 272;
void custom_exit(int status);

int main(){

  custom_printf("Setting calloc and free...\n");
  mbedtls_platform_set_calloc_free(calloc, free);
  custom_printf("Setting exit...\n");
  mbedtls_platform_set_exit(custom_exit);
  custom_printf("Setting printf...\n");
  mbedtls_platform_set_printf(custom_printf);
  custom_printf("Setting fprintf...\n");
  mbedtls_platform_set_fprintf(custom_fprintf);
  custom_printf("Setting snprintf...\n");
  mbedtls_platform_set_snprintf(snprintf);
  custom_printf("Setting vsnprintf...\n");
  mbedtls_platform_set_vsnprintf(vsnprintf);
  custom_printf("Setting crypto_interface...\n");
  mbedtls_platform_set_keystone_crypto_interface(crypto_interface);
  custom_printf("\n");
  // print tci sm and tci enclave
  char report[2048] = {0};
  attest_enclave((void*) report, "test", 5);
  struct report *parsed_report = (struct report*) report;
  print_hex_string("TCI enclave", parsed_report->enclave.hash, 64);
  print_hex_string("TCI sm", parsed_report->sm.hash, 64);
  mbedtls_printf("\n");

  // Client - Step 1: Create LDevID keypair
  mbedtls_printf("Step 1: Generating LDevID...\n\n");
  unsigned char pk[PUBLIC_KEY_SIZE] = {0};
  create_keypair(pk, 15);

  print_hex_string("LDevID PK", pk, PUBLIC_KEY_SIZE);
  mbedtls_printf("\n");

  // Client - Step 2: Get nonce from CA
  unsigned char nonce[] = {
    0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23,
    0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3
  };

  // Client - Step 3: Generate CSR
  mbedtls_printf("Step 2: Generating CSR...\n\n");
  unsigned char *certs[3];
  certs[0] = mbedtls_calloc(1, CERTS_MAX_LEN);
  if(certs[0]==NULL)
    EAPP_RETURN(-1);
  certs[1] = mbedtls_calloc(1, CERTS_MAX_LEN);
  if(certs[1]==NULL){
    mbedtls_free(certs[0]);
    EAPP_RETURN(-1);
  }
  certs[2] = mbedtls_calloc(1, CERTS_MAX_LEN);
  if(certs[2]==NULL){
    mbedtls_free(certs[0]);
    mbedtls_free(certs[1]);
    EAPP_RETURN(-1);
  }
  int sizes[3];
  get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);

  mbedtls_printf("Getting DICE certificates...\n");
  print_hex_string("certs[0]", certs[0], sizes[0]);
  print_hex_string("certs[1]", certs[1], sizes[1]);
  print_hex_string("certs[2]", certs[2], sizes[2]);
  mbedtls_printf("\n");

  int ret = 1;
  mbedtls_pk_context key;
  unsigned char attest_proof[512];
  size_t attest_proof_len;
  mbedtls_x509write_csr req;
  unsigned char key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT | MBEDTLS_X509_KU_DATA_ENCIPHERMENT | MBEDTLS_X509_KU_KEY_AGREEMENT;
  const char subject_name[] = "CN=Client,O=Enclave";

  mbedtls_printf("Generating attestation proof...\n");
  crypto_interface(1, nonce, NONCE_LEN, attest_proof, &attest_proof_len, pk);
  print_hex_string("attest_proof", attest_proof, attest_proof_len);
  mbedtls_printf("\n");

  mbedtls_x509write_csr_init(&req);
  mbedtls_pk_init(&key);

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_KEYSTONE_SHA3);
  mbedtls_printf("Setting md algorithm\n");

  ret = mbedtls_x509write_csr_set_key_usage(&req, key_usage);
  mbedtls_printf("Setting key usage - ret: %d\n", ret);

  ret = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
  mbedtls_printf("Setting subject - ret: %d\n", ret);
  
  ret = mbedtls_pk_parse_ed25519_key(&key, pk, PUBLIC_KEY_SIZE, 0);
  mbedtls_printf("Setting pk - ret: %d\n", ret);

  mbedtls_x509write_csr_set_key(&req, &key);
  mbedtls_printf("Setting pk context\n");

  ret = mbedtls_x509write_csr_set_nonce(&req, nonce);
  mbedtls_printf("Setting nonce - ret: %d\n", ret);

  ret = mbedtls_x509write_csr_set_attestation_proof(&req, attest_proof);
  mbedtls_printf("Setting attestation proof - ret: %d\n", ret);

  ret = mbedtls_x509write_csr_set_dice_certs(&req, (unsigned char **)certs, sizes);
  mbedtls_printf("Setting chain of certs - ret: %d\n", ret);

  mbedtls_printf("\n");

  #if PRINT_STRUCTS
  print_mbedtls_x509write_csr("CSR write struct", &req);
  #endif

  unsigned char out_csr[3072];
  int csr_len;

  csr_len = mbedtls_x509write_csr_der(&req, out_csr, 3072, NULL, NULL);
  mbedtls_printf("Writing CSR - ret: %d\n", csr_len);

  unsigned char *gen_csr = out_csr;
  int dif_csr = 3072-csr_len;
  gen_csr += dif_csr;

  print_hex_string("CSR", gen_csr, csr_len);
  mbedtls_printf("\n");

  mbedtls_pk_free(&key);
  mbedtls_x509write_csr_free(&req);

  mbedtls_free(certs[0]);
  mbedtls_free(certs[1]);
  mbedtls_free(certs[2]);

  // CA - Step 1: Send nonce
  // TODO

  // CA - Step 2: Parse and validate CSR
  mbedtls_printf("Step 3-A: Parsing CSR...\n\n");
  mbedtls_x509_csr csr;
  mbedtls_x509_csr_init(&csr);

  ret = mbedtls_x509_csr_parse_der(&csr, gen_csr, csr_len);
  mbedtls_printf("Parsing CSR - ret: %d\n", ret);
  mbedtls_printf("\n");

  #if PRINT_STRUCTS
  print_mbedtls_x509_csr("Parsed CSR", csr);
  #endif

  // verify CSR signature
  mbedtls_printf("Step 3-B: Verifying CSR...\n\n");
  unsigned char csr_hash[64] = {0};
  ret = mbedtls_md(mbedtls_md_info_from_type(csr.MBEDTLS_PRIVATE(sig_md)), csr.cri.p, csr.cri.len, csr_hash);
  mbedtls_printf("Hashing CSR- ret: %d\n", ret);
  #if PRINT_STRUCTS
  print_hex_string("Hash CSR", csr_hash, HASH_LEN);
  #endif
  ret = mbedtls_pk_verify_ext(csr.MBEDTLS_PRIVATE(sig_pk), csr.MBEDTLS_PRIVATE(sig_opts), &(csr.pk), csr.MBEDTLS_PRIVATE(sig_md), csr_hash, HASH_LEN, csr.MBEDTLS_PRIVATE(sig).p, csr.MBEDTLS_PRIVATE(sig).len);
  mbedtls_printf("Verify CSR signature - ret: %d\n", ret);
  mbedtls_printf("\n");

  // verify nonces equality
  ret = csr.nonce.len != NONCE_LEN;
  mbedtls_printf("Verify nonce len - ret: %d\n", ret);
  ret = memcmp(csr.nonce.p, nonce, NONCE_LEN);
  mbedtls_printf("Verify nonce value - ret: %d\n", ret);
  mbedtls_printf("\n");

  // parse trusted certificate
  uint32_t flags = 0;
  mbedtls_x509_crt trusted_certs;

  mbedtls_x509_crt_init(&trusted_certs);
  ret = mbedtls_x509_crt_parse_der(&trusted_certs, ref_cert_man, ref_cert_man_len);
  mbedtls_printf("Parsing Trusted Certificate - ret: %d\n", ret);

  #if PRINT_STRUCTS
  print_mbedtls_x509_cert("Trusted Certificate", trusted_certs);
  #endif

  // cert_chain.hash.p[15] = 0x56; // Used to break verification

  //  verify chain of certificates
  ret = mbedtls_x509_crt_verify_with_profile(&(csr.cert_chain), &trusted_certs, NULL, &mbedtls_x509_crt_profile_keystone, NULL, &flags, NULL, NULL);
  mbedtls_printf("Verifing Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
  mbedtls_printf("\n");

  mbedtls_x509_crt_free(&trusted_certs);

  // verify attestation proof
  unsigned char verification_pk[PUBLIC_KEY_SIZE] = {0};
  unsigned char reference_tci[HASH_LEN] = {0};
  unsigned char fin_hash[HASH_LEN] = {0};
  sha3_ctx_t ctx_hash;
  ret = getAttestationPublicKey(&csr, verification_pk);
  mbedtls_printf("Getting SM PK - ret: %d\n", ret);

  print_hex_string("SM PK", verification_pk, PUBLIC_KEY_SIZE);

  ret = getReferenceTCI(&csr, reference_tci);
  mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
  print_hex_string("Reference Enclave TCI", reference_tci, HASH_LEN);

  sha3_init(&ctx_hash, HASH_LEN);
  sha3_update(&ctx_hash, nonce, NONCE_LEN);
  sha3_update(&ctx_hash, reference_tci, HASH_LEN);
  sha3_update(&ctx_hash, mbedtls_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE);
  sha3_final(fin_hash, &ctx_hash);

  /*
  ret = ed25519_verify(csr.MBEDTLS_PRIVATE(sig).p, fin_hash, HASH_LEN, verification_pk)==1?0:1;
  mbedtls_printf("Verifying attestation proof - ret: %d\n", ret);
  mbedtls_printf("\n");
  */
  mbedtls_pk_context key_ver;
  mbedtls_pk_init(&key_ver);
  ret = mbedtls_pk_parse_ed25519_key(&key_ver, verification_pk, PUBLIC_KEY_SIZE, 0);
  mbedtls_printf("Parsing SM PK - ret: %d\n", ret);

  ret = mbedtls_pk_verify_ext(MBEDTLS_PK_ED25519, NULL, &key_ver, MBEDTLS_MD_KEYSTONE_SHA3, fin_hash, HASH_LEN, csr.attestation_proof.p, csr.attestation_proof.len);
  mbedtls_printf("Verifying attestation proof - ret: %d\n", ret);
  mbedtls_printf("\n");

  mbedtls_pk_free(&key_ver);

  // CA - Step 3: Generate Enclave Certificate
  mbedtls_printf("Step 4: Generating Certificate...\n\n");

  mbedtls_x509write_cert cert_encl;
  mbedtls_x509write_crt_init(&cert_encl);

  ret = mbedtls_x509write_crt_set_issuer_name(&cert_encl, "O=Certificate Authority");
  mbedtls_printf("Setting issuer - ret: %d\n", ret);
  
  ret = mbedtls_x509write_crt_set_subject_name(&cert_encl, "CN=Client1,O=Certificate Authority");
  mbedtls_printf("Setting subject - ret: %d\n", ret);

  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);
  
  ret = mbedtls_pk_parse_ed25519_key(&issu_key, sanctum_ca_private_key, PRIVATE_KEY_SIZE, PARSE_PRIVATE_KEY);
  mbedtls_printf("Parsing issuer pk - ret: %d\n", ret);

  ret = mbedtls_pk_parse_ed25519_key(&issu_key, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
  mbedtls_printf("Parsing issuer sk - ret: %d\n", ret);

  ret = mbedtls_pk_parse_ed25519_key(&subj_key, mbedtls_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
  mbedtls_printf("Parsing subject pk - ret: %d\n", ret);

  mbedtls_x509write_crt_set_subject_key(&cert_encl, &subj_key);
  mbedtls_printf("Setting subject key\n");

  mbedtls_x509write_crt_set_issuer_key(&cert_encl, &issu_key);
  mbedtls_printf("Setting issuer keys\n");
  
  unsigned char serial[] = {0xAB, 0xAB, 0xAB};

  ret = mbedtls_x509write_crt_set_serial_raw(&cert_encl, serial, 3);
  mbedtls_printf("Setting serial - ret: %d\n", ret);
  
  mbedtls_x509write_crt_set_md_alg(&cert_encl, MBEDTLS_MD_KEYSTONE_SHA3);
  mbedtls_printf("Setting md algorithm\n");
  
  ret = mbedtls_x509write_crt_set_validity(&cert_encl, "20230101000000", "20240101000000");
  mbedtls_printf("Setting validity - ret: %d\n", ret);

  char oid_ext[] = {0xff, 0x20, 0xff};

  ret = mbedtls_x509write_crt_set_extension(&cert_encl, oid_ext, 3, 0, reference_tci, HASH_LEN);
  mbedtls_printf("Setting tci - ret: %d\n", ret);

  mbedtls_printf("\n");
  // Writing certificate
  
  unsigned char cert_der[1024];
  int effe_len_cert_der;
  size_t len_cert_der_tot = 1024;

  ret = mbedtls_x509write_crt_der(&cert_encl, cert_der, len_cert_der_tot, NULL, NULL);
  mbedtls_printf("Writing Enclave Certificate - ret: %d\n", ret);
  effe_len_cert_der = ret;
  
  unsigned char *cert_real = cert_der;
  int dif  = 1024-effe_len_cert_der;
  cert_real += dif;

  print_hex_string("Enclave Certificate", cert_real, effe_len_cert_der);

  mbedtls_pk_free(&issu_key);
  mbedtls_pk_free(&subj_key);
  mbedtls_x509write_crt_free(&cert_encl);
  mbedtls_x509_csr_free(&csr);

  // parse enclave certificate
  mbedtls_x509_crt cert_gen;
  mbedtls_x509_crt_init(&cert_gen);
  ret = mbedtls_x509_crt_parse_der(&cert_gen, cert_real, effe_len_cert_der);
  mbedtls_printf("Parsing Enclave Certificate - ret: %d\n", ret);
  mbedtls_printf("\n");

  #if PRINT_STRUCTS
  print_mbedtls_x509_cert("Enclave Certificate", cert_gen);
  #endif

  mbedtls_x509_crt_free(&cert_gen);

  EAPP_RETURN(0);
}

void custom_exit(int status){
    EAPP_RETURN(status);
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9

/*** Code to generate CA cert ***/
/*
  int ret;
  unsigned char sanctum_ca_private_key[PRIVATE_KEY_SIZE];
  unsigned char sanctum_ca_public_key[PUBLIC_KEY_SIZE];
  mbedtls_x509write_cert cert_ca;
  mbedtls_x509write_crt_init(&cert_ca);

  // Setting the name of the issuer of the cert

  ed25519_create_keypair(sanctum_ca_public_key, sanctum_ca_private_key, seed);

  print_hex_string("CA-SK", (unsigned char *)sanctum_ca_private_key, PRIVATE_KEY_SIZE);
  print_hex_string("CA-PK", (unsigned char *)sanctum_ca_public_key, PUBLIC_KEY_SIZE);
  
  ret = mbedtls_x509write_crt_set_issuer_name(&cert_ca, "O=Certificate Authority");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name(&cert_ca, "O=Certificate Authority");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_ca;
  mbedtls_pk_init(&subj_key_ca);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_ca;
  mbedtls_pk_init(&issu_key_ca);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_ed25519_key(&issu_key_ca, sanctum_ca_private_key, PRIVATE_KEY_SIZE, PARSE_PRIVATE_KEY);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_ed25519_key(&issu_key_ca, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_ed25519_key(&subj_key_ca, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_ca[] = {0x0F, 0x0F, 0x0F};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_ca, &subj_key_ca);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_ca, &issu_key_ca);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_ca, serial_ca, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_ca, MBEDTLS_MD_KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_ca, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_x509write_crt_set_basic_constraints(&cert_ca, 1, 10);
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der_ca[1024];
  int effe_len_cert_der_ca;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_ca, cert_der_ca, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_ca = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_ca = cert_der_ca;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_ca = 1024-effe_len_cert_der_ca;
  // cert_real points to the starts of the cert in der format
  cert_real_ca += dif_ca;

  mbedtls_pk_free(&issu_key_ca);
  mbedtls_pk_free(&subj_key_ca);
  mbedtls_x509write_crt_free(&cert_ca);
  print_hex_string("Cert generated", cert_real_ca, effe_len_cert_der_ca);
*/