/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "app/eapp_utils.h"
#include "edge/edge_call.h"
#include "app/syscall.h"
#include "app/malloc.h"

#include "eapp/eapp_net.h"
#include "eapp/eapp_crt.h"

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/base64.h"
#include "mbedtls/print.h"
#include "mbedtls/keystone_ext.h"
// #include "certs.h"
#include "eapp/printf.h"
#include "custom_certs.h"
#include "riscv_time.h"
#include "mbedtls/ed25519.h"
// #include "eapp/ref_certs.h"
// #include "custom_functions.h"

// #include <stdio.h>
// #include <time.h>
#include <string.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define CERTS_MAX_LEN           1024
#define CSR_MAX_LEN             3072
#define ATTEST_DATA_MAX_LEN     1024
#define NONCE_MAX_LEN           128
#define BUF_SIZE                2048

#define NET_SUCCESS     1
#define HANDLER_ERROR   2
#define GOTO_EXIT       3
#define GOTO_RESET      4

#define STATUS_OK           0
#define STATUS_BAD_REQUEST  1
#define STATUS_SERVER_ERROR 2
#define STATUS_FORBIDDEN    3

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

#define COMPARE_CRYPTO_OP 0

#define TRUSTED_CHANNEL 1

typedef unsigned char byte;

struct enclave_report
{
  byte hash[KEYSTONE_HASH_MAX_SIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAX_LEN];
  byte signature[KEYSTONE_PK_SIGNATURE_MAX_SIZE];
};

struct sm_report
{
  byte hash[KEYSTONE_HASH_MAX_SIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[KEYSTONE_PK_SIGNATURE_MAX_SIZE];
};

struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

int get_nonce(unsigned char *buf, size_t buf_len, unsigned char *nonce, size_t *nonce_len);

int get_null(unsigned char *buf, size_t buf_len, unsigned char *empty, size_t *empty_len);

int get_crt(unsigned char *buf, size_t buf_len, unsigned char *crt, size_t *len);

void custom_exit(int status);

int create_csr(unsigned char *pk, unsigned char *nonce, unsigned char *certs[], int *sizes, unsigned char *csr, size_t *csr_len);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len));

int test_connection_Bob(mbedtls_x509_crt *crt_Alice, unsigned char *ldevid_pk);

void my_debug(void *ctx, int level, const char *file, int line, const char *str);

int send_buf_test(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf_test(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len));

int main(void)
{
    int ret = 1;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[BUF_SIZE];
    char report[BUF_SIZE] = {0};
    struct report *parsed_report;
    unsigned char pk[PUBLIC_KEY_SIZE] = {0};
    unsigned char nonce[NONCE_MAX_LEN];
    unsigned char csr[CSR_MAX_LEN];
    unsigned char ldevid_crt[CERTS_MAX_LEN] = {0};
    int ldevid_crt_len = 0;
    mbedtls_x509_crt ldevid_cert_parsed;
    size_t csr_len;
    size_t ldevid_ca_cert_len = 0;
    unsigned char ldevid_ca_cert[2*CERTS_MAX_LEN] = {0};
    mbedtls_x509_crt cert_gen;
    unsigned char enc_csr[CSR_MAX_LEN];
    size_t enc_csr_len;
    unsigned char *certs[3];
    int sizes[3];
    size_t body_len;
    mbedtls_pk_context ldevid_parsed;
    // const char *pers = "ssl_client1";
    // mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    #if PERFORMANCE_TEST
    ticks_t t_start_global, t_end_global, t_start, t_end, t_diff;
    #endif

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
    
    // Print TCI SM and TCI Enclave
    mbedtls_printf("Getting TCI values...\n");
    attest_enclave((void*) report, "test", 5);
    parsed_report = (struct report*) report;
    print_hex_string("TCI enclave-alice", parsed_report->enclave.hash, KEYSTONE_HASH_MAX_SIZE);
    print_hex_string("TCI sm", parsed_report->sm.hash, KEYSTONE_HASH_MAX_SIZE);
    mbedtls_printf("\n");

    // Try to read certificate in memory
    mbedtls_printf("Retrieving crt from memory...\n");
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    ret = read_crt((unsigned char *) ldevid_ca_cert, &ldevid_ca_cert_len);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    #endif
    if(ret != 0) {
        if(ret != -4)
            mbedtls_printf("Error in retrieving crt\n");
        else
            mbedtls_printf("Integrity check failed\n");
    } else {
        print_hex_string("Stored crt", ldevid_ca_cert, ldevid_ca_cert_len);
    }
    mbedtls_printf("\n");

    #if PERFORMANCE_TEST
    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for reading crt: %lu\n", t_diff);

    t_start_global = get_time_inline();
    #endif

    // Step 1: Create LDevID keypair
    mbedtls_printf("1.1 Generating LDevID...\n");
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    create_keypair(pk, 15, ldevid_crt, &ldevid_crt_len);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for generating LDevID: %lu\n", t_diff);
    #endif

    print_hex_string("LDevID PK", pk, PUBLIC_KEY_SIZE);
    print_hex_string("LDevID crt", ldevid_crt, ldevid_crt_len);
    // mbedtls_x509_crt_free(&ldevid_cert_parsed);
    mbedtls_printf("\n");

    #if PERFORMANCE_TEST && COMPARE_CRYPTO_OP
    unsigned char new_pk[PUBLIC_KEY_SIZE];
    unsigned char new_sk[PRIVATE_KEY_SIZE];
    unsigned char seed[PRIVATE_KEY_SIZE] = { 
        0x30, 0x82, 0x05, 0x32, 0x30, 0x82, 0x04, 0xe2, 0x02, 0x01, 0x00, 0x30, 0x45, 0x31, 0x0c, 0x30, 
        0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x42, 0x6f, 0x62, 0x31, 0x35, 0x30, 0x33, 0x06, 
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x2c, 0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x2d, 0x62, 0x62, 
        0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x2d, 0x62, 0x62, 0x62, 0x62, 0x2d, 0x62, 0x62, 0x62, 0x62 
    };
    unsigned char signature[KEYSTONE_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len;
    ed25519_create_keypair(new_pk, new_sk, seed);

    t_start = get_time_inline();
    ed25519_sign(signature, seed, PRIVATE_KEY_SIZE, new_pk, new_sk);
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for signing - standard: %lu\n", t_diff);

    t_start = get_time_inline();
    crypto_interface(2, seed, PRIVATE_KEY_SIZE, signature, &sig_len, pk);
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for signing - crypto_interface: %lu\n", t_diff);
    #endif

    certs[0] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[0]==NULL){
        mbedtls_exit(-1);
    }
    certs[1] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[1]==NULL){
        mbedtls_free(certs[0]);
        mbedtls_exit(-1);
    }
    certs[2] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[2]==NULL){
        mbedtls_free(certs[0]);
        mbedtls_free(certs[1]);
        mbedtls_exit(-1);
    }

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for getting DICE chain: %lu\n", t_diff);
    #endif

    mbedtls_printf("2.1 Getting DICE certificates...\n");
    print_hex_string("LAK crt", certs[0], sizes[0]);
    print_hex_string("SM ECA crt", certs[1], sizes[1]);
    print_hex_string("DevRoot crt", certs[2], sizes[2]);

    mbedtls_printf("\n");

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    mbedtls_x509_crt_init(&ldevid_cert_parsed);
    ret = mbedtls_x509_crt_parse_der(&ldevid_cert_parsed, ldevid_crt, ldevid_crt_len);
    mbedtls_printf("Parsing LDevID crt - ret: %d\n", ret);
    if(ret != 0)
        mbedtls_exit(-1);
    ret = mbedtls_x509_crt_parse_der(&ldevid_cert_parsed, certs[1], sizes[1]);
    mbedtls_printf("Parsing SM ECA crt - ret: %d\n", ret);
    if(ret != 0)
        mbedtls_exit(-1);
    ret = mbedtls_x509_crt_parse_der(&ldevid_cert_parsed, certs[2], sizes[2]);
    mbedtls_printf("Parsing DevRoot crt - ret: %d\n", ret);
    if(ret != 0)
        mbedtls_exit(-1);
    mbedtls_printf("\n");

    // Step 2: Open TLS connection to CA

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    custom_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&ldevid_parsed);

    /*
    mbedtls_printf("\n[EA]  . Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen((char*)pers))) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");
    */

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[EA]  . Loading the CA root certificate ...");

    ret =  mbedtls_pk_parse_ed25519_key(&ldevid_parsed, (const unsigned char *) pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    if (ret != 0) {
        mbedtls_printf(" failed\n[EA]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n[EA]  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("[EA]  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);

    if ((ret = custom_net_connect(&server_fd, SERVER_NAME,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("[EA]  . Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &ldevid_cert_parsed, &ldevid_parsed)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, "CA")) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_net_send, custom_net_recv, NULL);

    /*
     * 3. Handshake
     */
    mbedtls_printf("[EA]  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Verify the server certificate
     */
    mbedtls_printf("[EA]  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        mbedtls_printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
#endif
    } else {
        mbedtls_printf(" ok\n");
    }

    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for establishing TLS connection: %lu\n", t_diff);
    #endif

    // Step 3: Retrieve the nonce
    mbedtls_printf("\n2.5 Getting nonce...\n");

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif

    // Send request to get the nonce
    len = sprintf((char *) buf, GET_NONCE_REQUEST);

    if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
        goto exit;
    }

    // Read the nonce from the response

    if((ret = recv_buf(&ssl, buf, &len, nonce, NULL, get_nonce))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = len;
        goto exit;
    }

    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for getting nonce: %lu\n", t_diff);
    #endif

    mbedtls_printf("\n");
    // Nonce contained in the response
    print_hex_string("nonce", nonce, NONCE_LEN);
    mbedtls_printf("\n");

    // nonce[10] = '\x00';

    // Step 4: Generate CSR
    mbedtls_printf("Generating CSR...\n");

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    ret = create_csr(pk, nonce, certs, sizes, csr, &csr_len);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    #endif
    if(ret!=0){
        goto exit;
    }
    #if PERFORMANCE_TEST
    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for generating CSR: %lu\n", t_diff);
    #endif
    
    // Generated CSR
    print_hex_string("CSR", csr, csr_len);
    mbedtls_printf("\n");

    // Step 5: Send CSR to CA
    mbedtls_printf("2.18 Sending CSR...\n");

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif

    // Send CSR
    if((ret = mbedtls_base64_encode(enc_csr, CSR_MAX_LEN, &enc_csr_len, csr, csr_len))!=0) {
        goto exit;
    }
    body_len = sizeof(POST_CSR_REQUEST_END)+enc_csr_len-3;
    // mbedtls_printf("enc_csr_len: %lu\n", enc_csr_len);
    len = sprintf((char *) buf, POST_CSR_REQUEST_START, body_len);
    len += sprintf((char *) buf+len, POST_CSR_REQUEST_END, enc_csr);

    if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
        goto exit;
    }

    // Step 6: Get the certificate issued by CA
    mbedtls_printf(" ...\n");
    mbedtls_printf("\n2.24 Getting new LDevID crt...\n");

    // Get crt from the response
    if((ret = recv_buf(&ssl, buf, &len, ldevid_ca_cert, &ldevid_ca_cert_len, get_crt))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = len;
        goto exit;
    }

    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for getting new crt: %lu\n", t_diff);
    #endif
    
    mbedtls_printf(" ...\n\n");

    // Step 7: Close the connection

    mbedtls_printf("Connected using %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    mbedtls_ssl_close_notify(&ssl);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for closing connection: %lu\n", t_diff);
    #endif
    mbedtls_printf("\n");
    
    
    print_hex_string("new LDevID crt", ldevid_ca_cert, ldevid_ca_cert_len);
    mbedtls_printf("\n");

    #if PERFORMANCE_TEST
    t_end_global = get_time_inline();
    t_diff = t_end_global-t_start_global;
    mbedtls_printf("\nTicks for certification protocol: %lu\n", t_diff);

    t_start = get_time_inline();
    #endif
    // Parse the received certificate
    mbedtls_x509_crt_init(&cert_gen);
    #if TRUSTED_CHANNEL
    ret = mbedtls_x509_crt_parse_der(&cert_gen, ldevid_ca_cert, ldevid_ca_cert_len);
    #else
    ret = mbedtls_x509_crt_parse(&cert_gen, (const unsigned char*) alice_cert_pem, alice_cert_pem_len);
    #endif
    mbedtls_printf("Parsing new LDevID crt - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_crt_free(&cert_gen);
        goto exit;
    }
    mbedtls_printf("\n");

    ret = test_connection_Bob(&cert_gen, pk);
    mbedtls_x509_crt_free(&cert_gen);
    if(ret != 0) {
        goto exit;
    }
    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for channel to other enclave: %lu\n", t_diff);
    #endif

    #if PRINT_STRUCTS
    print_mbedtls_x509_cert("new LDevID crt", cert_gen);
    #endif

    // Store the certificate
    mbedtls_printf("\nStoring the certificate in memory...\n");
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    ret = store_crt(ldevid_ca_cert, ldevid_ca_cert_len);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    #endif
    if(ret != 0) {
        mbedtls_printf("Error in storing LDevID_crt\n");
        goto exit;
    }

    #if PERFORMANCE_TEST
    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for storing crt: %lu\n", t_diff);
    #endif

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[EA] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    custom_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&ldevid_cert_parsed);
    mbedtls_pk_free(&ldevid_parsed);
    mbedtls_free(certs[0]);
    mbedtls_free(certs[1]);
    mbedtls_free(certs[2]);
    // mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}

void custom_exit(int status){
    EAPP_RETURN(status);
}

int get_nonce(unsigned char *buf, size_t buf_len, unsigned char *nonce, size_t *nonce_len){
    int i, ret = 0;
    unsigned char enc_nonce[NONCE_MAX_LEN] = {0};
    size_t enc_nonce_len = 0;
    size_t dec_nonce_len = 0;
    size_t body_len = 0;

    if(memcmp(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400))==0) {
        mbedtls_printf("\nResponse: Bad Request\n");
        return -1;
    }

    if(memcmp(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500))==0) {
        mbedtls_printf("\nResponse: Internal Server Error\n");
        return -1;
    }

    if(memcmp(buf, HTTP_RESPONSE_403, sizeof(HTTP_RESPONSE_403))==0) {
        mbedtls_printf("\nResponse: Forbidden\n");
        return -1;
    }

    if(memcmp(buf, HTTP_NONCE_RESPONSE_START, sizeof(HTTP_NONCE_RESPONSE_START)-1)!=0) {
        mbedtls_printf("\nCannot read nonce 1\n\n");
        return -1;
    }
    i = sizeof(HTTP_NONCE_RESPONSE_START)-1;

    while(buf[i] >= '0' && buf[i] <= '9'){
        body_len *= 10;
        body_len += buf[i] - '0';
        i++;
    }

    if(body_len == 0 || body_len > buf_len-i-4) {
        mbedtls_printf("\nReceived less bytes than expected\n\n");
        return -1;
    }

    enc_nonce_len = body_len-sizeof(HTTP_NONCE_RESPONSE_MIDDLE)-sizeof(HTTP_NONCE_RESPONSE_END)+6;
    // mbedtls_printf("body_len: %lu, enc_nonce_len: %lu\n", body_len, enc_nonce_len);

    if(enc_nonce_len <= 0) {
        mbedtls_printf("\nReceived less bytes than expected\n\n");
        return -1;
    }

    if(memcmp(buf+i, HTTP_NONCE_RESPONSE_MIDDLE, sizeof(HTTP_NONCE_RESPONSE_MIDDLE)-1)!=0) {
        mbedtls_printf("\nCannot read nonce 2\n\n");
        return -1;
    }
    i += sizeof(HTTP_NONCE_RESPONSE_MIDDLE)-1;

    memcpy(enc_nonce, buf+i, enc_nonce_len);

    if(memcmp(buf+i+enc_nonce_len, HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END))!=0){
        mbedtls_printf("\nCannot read nonce 3\n\n");
        return -1;
    }

    ret = mbedtls_base64_decode(nonce, NONCE_MAX_LEN, &dec_nonce_len, enc_nonce, enc_nonce_len);
    return ret || (dec_nonce_len != NONCE_LEN);
}

int get_crt(unsigned char *buf, size_t buf_len, unsigned char *crt, size_t *crt_len) {
    int i;
    unsigned char enc_crt[CERTS_MAX_LEN] = {0};
    size_t enc_crt_len = 0;
    size_t body_len = 0;

    if(memcmp(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400))==0) {
        mbedtls_printf("\nResponse: Bad Request\n\n");
        return -1;
    }

    if(memcmp(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500))==0) {
        mbedtls_printf("\nResponse: Internal Server Error\n\n");
        return -1;
    }

    if(memcmp(buf, HTTP_RESPONSE_403, sizeof(HTTP_RESPONSE_403))==0) {
        mbedtls_printf("\nResponse: Forbidden\n");
        return -1;
    }

    if(memcmp(buf, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1)!=0) {
        mbedtls_printf("\nCannot read certificate 1\n\n");
        return -1;
    }
    i = sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1;

    while(buf[i] >= '0' && buf[i] <= '9'){
        body_len *= 10;
        body_len += buf[i] - '0';
        i++;
    }

    if(body_len == 0 || body_len > buf_len-i-4) {
        mbedtls_printf("\nReceived less bytes than expected\n\n");
        return -1;
    }

    enc_crt_len = body_len-sizeof(HTTP_CERTIFICATE_RESPONSE_MIDDLE)-sizeof(HTTP_CERTIFICATE_RESPONSE_END)+6;
    // mbedtls_printf("body_len: %lu, enc_crt_len: %lu\n", body_len, enc_crt_len);

    if(enc_crt_len <= 0) {
        mbedtls_printf("\nReceived less bytes than expected\n\n");
        return -1;
    }

    if(memcmp(buf+i, HTTP_CERTIFICATE_RESPONSE_MIDDLE, sizeof(HTTP_CERTIFICATE_RESPONSE_MIDDLE)-1)!=0) {
        mbedtls_printf("\nCannot read certificate 2\n\n");
        return -1;
    }
    i += sizeof(HTTP_CERTIFICATE_RESPONSE_MIDDLE)-1;

    memcpy(enc_crt, buf+i, enc_crt_len);

    if(memcmp(buf+i+enc_crt_len, HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END))!=0){
        mbedtls_printf("\nCannot read certificate 3\n\n");
        return -1;
    }

    return mbedtls_base64_decode(crt, CERTS_MAX_LEN, crt_len, enc_crt, enc_crt_len);
}

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len){
    int ret;
    mbedtls_printf("[EA]  > Write to server:");
    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_write returned %d\n\n", ret);
            return ret;
        }
    }

    *len = ret;
    mbedtls_printf(" %d bytes written\n\n%s", *len, (char *) buf);
    return NET_SUCCESS;
}

// buf must be BUF_SIZE byte long
int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len)){
    int ret;
    mbedtls_printf("[EA]  < Read from server:");
    do {
        *len = BUF_SIZE - 1;
        memset(buf, 0, BUF_SIZE);
        ret = mbedtls_ssl_read(ssl, buf, *len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }

        if (ret < 0) {
            mbedtls_printf("failed\n[EA]  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\n[EA] EOF\n\n");
            break;
        }

        *len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", *len, (char *) buf);

        // Get the data from the response
        if((ret = handler(buf, *len, data, data_len)) != 0){
            *len = ret;
            return HANDLER_ERROR;
        } 
        ret = NET_SUCCESS;
        break;

    } while (1);
    return ret;
}

int create_csr(unsigned char *pk, unsigned char *nonce, unsigned char *certs[], int *sizes, unsigned char *csr, size_t *csr_len){
    // unsigned char *certs[3];
    // int sizes[3];
    mbedtls_pk_context key;
    unsigned char attest_proof[ATTEST_DATA_MAX_LEN];
    size_t attest_proof_len;
    mbedtls_x509write_csr req;
    unsigned char key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    const char subject_name[] = "CN=Alice,O=Enclave-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    unsigned char out_csr[CSR_MAX_LEN];
    #if PERFORMANCE_TEST
    ticks_t t_start, t_end, t_diff;
    #endif

    /*
    certs[0] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[0]==NULL)
        mbedtls_exit(-1);
    certs[1] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[1]==NULL){
        mbedtls_free(certs[0]);
        mbedtls_exit(-1);
    }
    certs[2] = mbedtls_calloc(1, CERTS_MAX_LEN);
    if(certs[2]==NULL){
        mbedtls_free(certs[0]);
        mbedtls_free(certs[1]);
        mbedtls_exit(-1);
    }

    get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);

    mbedtls_printf("Getting DICE certificates...\n");
    print_hex_string("certs[0]", certs[0], sizes[0]);
    print_hex_string("certs[1]", certs[1], sizes[1]);
    print_hex_string("certs[2]", certs[2], sizes[2]);
    mbedtls_printf("\n");
    */

    int ret = 0;

    mbedtls_printf("2.11 Generating attestation evidence signature...\n");
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    crypto_interface(1, nonce, NONCE_LEN, attest_proof, &attest_proof_len, pk);
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    #endif
    print_hex_string("attest_evd_sign", attest_proof, attest_proof_len);
    // mbedtls_printf("\n");

    #if PERFORMANCE_TEST
    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for getting attestation evidence signature: %lu\n", t_diff);
    #endif
    // attest_proof[10] = '\x00';

    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&key);

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_KEYSTONE_SHA3);
    mbedtls_printf("Setting md algorithm\n");

    ret = mbedtls_x509write_csr_set_key_usage(&req, key_usage);
    mbedtls_printf("Setting key usage - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;

    ret = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
    mbedtls_printf("Setting subject - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;
    
    ret = mbedtls_pk_parse_ed25519_key(&key, pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Setting PK - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;

    mbedtls_x509write_csr_set_key(&req, &key);
    mbedtls_printf("Setting PK context\n");

    ret = mbedtls_x509write_csr_set_nonce(&req, nonce);
    mbedtls_printf("Setting nonce - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;

    ret = mbedtls_x509write_csr_set_attestation_proof(&req, attest_proof);
    mbedtls_printf("Setting attestation evidence signature - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;

    ret = mbedtls_x509write_csr_set_dice_certs(&req, (unsigned char **)certs, sizes);
    mbedtls_printf("Setting chain of DICE certs - ret: %d\n", ret);
    if(ret != 0)
        goto end_create_csr;

    mbedtls_printf("\n");

    #if PRINT_STRUCTS
    print_mbedtls_x509write_csr("CSR write struct", &req);
    #endif

    ret = mbedtls_x509write_csr_der(&req, out_csr, CSR_MAX_LEN, NULL, NULL);
    mbedtls_printf("Writing CSR - ret: %d\n", *csr_len);
    if(ret <= 0)
        goto end_create_csr;

    *csr_len = ret;
    unsigned char *gen_csr = out_csr;
    int dif_csr = CSR_MAX_LEN-(*csr_len);
    gen_csr += dif_csr;

    memcpy(csr, gen_csr, *csr_len);
    ret = 0;

end_create_csr:
    mbedtls_pk_free(&key);
    mbedtls_x509write_csr_free(&req);

    /*
    mbedtls_free(certs[0]);
    mbedtls_free(certs[1]);
    mbedtls_free(certs[2]);
    */
    return ret;
}

int test_connection_Bob(mbedtls_x509_crt *crt_Alice, unsigned char *ldevid_pk) {
    int ret, msg; 
    uint32_t flags;
    size_t len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[BUF_SIZE];
    // const char *pers = "ssl_server";
    // mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    // mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif
    #if PERFORMANCE_TEST
    ticks_t t_start, t_end, t_diff;

    t_start = get_time_inline();
    #endif

    custom_net_init(&listen_fd);
    custom_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif
    // mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&pkey);
    // mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1. Seed the RNG
     */
    /*
    mbedtls_printf("[EA]  . Seeding the random number generator...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen((char*)pers))) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");
    */

    /*
     * 2. Load the certificates and private RSA key
     */
    mbedtls_printf("[EA]  . Loading the server cert. and key...");

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[EA]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit_test;
    }

    #if TRUSTED_CHANNEL
    ret =  mbedtls_pk_parse_ed25519_key(&pkey, (const unsigned char *) ldevid_pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    #else
    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) alice_key_pem, alice_key_pem_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    #endif
    if (ret != 0) {
        mbedtls_printf(" failed\n[EA]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    mbedtls_printf("[EA]  . Bind on https://localhost:8062/ ...");

    if ((ret = custom_net_bind(&listen_fd, NULL, "8062", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("[EA]  . Setting up the SSL data....");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    // mbedtls_ssl_conf_cert_profile(&conf,&mbedtls_x509_crt_profile_keystone);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, crt_Alice, &pkey)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit_test;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");

reset_test:
    msg = STATUS_OK;
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[EA] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    custom_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("[EA]  . Waiting for a remote connection ...");

    if ((ret = custom_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n[EA]  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, custom_net_send, custom_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("[EA]  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset_test;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Verify the client certificate
     */
    mbedtls_printf("[EA]  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        mbedtls_printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
#endif
    } else {
        mbedtls_printf(" ok\n");
    }

    #if PERFORMANCE_TEST
    t_end = get_time_inline();

    t_diff = t_end-t_start;
    mbedtls_printf("\nTicks for channel setup: %lu\n", t_diff);
    #endif

    /* Send and receive data*/
    if((ret = recv_buf_test(&ssl, buf, &len, NULL, NULL, get_null))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) {
            ret = len;
            msg = STATUS_BAD_REQUEST;
            goto send_answer_test;
        }
        goto reset_test;
    }

    len = sprintf((char*) buf, "Hello, I'm Alice!\r\n");

    // Send the response
    if((ret = send_buf_test(&ssl, buf, &len))!=NET_SUCCESS){
        if(ret == GOTO_EXIT){
            ret = len;
            goto exit_test;
        }
        if(ret == GOTO_RESET){
            ret = len;
            goto reset_test;
        }
        goto reset_test;
    }
    
    mbedtls_printf("[EA]  . Closing the connection to Enclave...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset_test;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;

send_answer_test:

    if(msg != STATUS_OK) {
        switch(msg) {
            case STATUS_BAD_REQUEST:
                memcpy(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
                len = sizeof(HTTP_RESPONSE_400);
                break;
            case STATUS_FORBIDDEN:
                memcpy(buf, HTTP_RESPONSE_403, sizeof(HTTP_RESPONSE_403));
                len = sizeof(HTTP_RESPONSE_403);
                break;
            default:
                memcpy(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500));
                len = sizeof(HTTP_RESPONSE_500);
                break;
        }
        int ret2 = 0;
        if((ret2 = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
            if(ret2 == GOTO_EXIT){
                ret = len;
            } else if(ret2 == GOTO_RESET){
                ret = len;
                goto reset_test;
            } else {
                ret = ret2;
            }
        }
        if(ret2 != GOTO_EXIT) {
            goto reset_test;
        }
    }
            
exit_test:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[EA] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    custom_net_free(&client_fd);
    custom_net_free(&listen_fd);
    // mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    // mbedtls_entropy_free(&entropy);
    return ret;
}

void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);

    mbedtls_printf("%s:%04d: %s", file, line, str);
}

int get_null(unsigned char *buf, size_t buf_len, unsigned char *empty, size_t *empty_len) {
    return 0;
}

int send_buf_test(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len) {
    int ret;
    mbedtls_printf("[EA]  > Write to client:");

    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[EA]  ! peer closed the connection\n\n");
            *len = ret;
            return GOTO_RESET;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EA]  ! mbedtls_ssl_write returned %d\n\n", ret);
            *len = ret;
            return GOTO_EXIT;
        }
    }

    *len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", *len, (char *) buf);
    return NET_SUCCESS;
}

int recv_buf_test(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len)) {
    int ret;
    mbedtls_printf("[EA]  < Read from client:");
    do {
        *len = BUF_SIZE - 1;
        memset(buf, 0, BUF_SIZE);
        ret = mbedtls_ssl_read(ssl, buf, *len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret);
                    break;
            }

            break;
        }

        *len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", *len, (char *) buf);

        if (ret > 0) {
            if((ret = handler(buf, *len, data, data_len))!=0) {
                *len = ret;
                return HANDLER_ERROR;
            }
            ret = NET_SUCCESS;
            break;
        }
    } while (1);
    return ret;
}
