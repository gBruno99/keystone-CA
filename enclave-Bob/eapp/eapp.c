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
#include "eapp/printf.h"
#include "custom_certs.h"
#include <string.h>
#include "riscv_time.h"

#define CERTS_MAX_LEN           1024
#define CSR_MAX_LEN             3072
#define ATTEST_DATA_MAX_LEN     1024
#define NONCE_MAX_LEN           128
#define BUF_SIZE                2048

#define NET_SUCCESS     1
#define HANDLER_ERROR   2

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

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

int get_crt(unsigned char *buf, size_t buf_len, unsigned char *crt, size_t *len);

int get_null(unsigned char *buf, size_t buf_len, unsigned char *empty, size_t *empty_len);

void custom_exit(int status);

int create_csr(unsigned char *pk, unsigned char *nonce, unsigned char *certs[], int *sizes, unsigned char *csr, size_t *csr_len);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len));

int test_connection_Alice(mbedtls_x509_crt *crt_Bob, unsigned char *ldevid_pk);

void my_debug(void *ctx, int level, const char *file, int line, const char *str);

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
    ticks_t t_start, t_end, t_diff;
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
    print_hex_string("TCI enclave-bob", parsed_report->enclave.hash, KEYSTONE_HASH_MAX_SIZE);
    print_hex_string("TCI sm", parsed_report->sm.hash, KEYSTONE_HASH_MAX_SIZE);
    mbedtls_printf("\n");

    // Try to read certificate in memory
    mbedtls_printf("Retrieving crt from memory...\n");
    ret = read_crt((unsigned char *) ldevid_ca_cert, &ldevid_ca_cert_len);
    if(ret != 0) {
        if(ret != -4)
            mbedtls_printf("Error in retrieving crt\n");
        else
            mbedtls_printf("Integrity check failed\n");
    } else {
        print_hex_string("Stored crt", ldevid_ca_cert, ldevid_ca_cert_len);
    }
    mbedtls_printf("\n");

    // Step 1: Create LDevID keypair
    mbedtls_printf("1.1 Generating LDevID...\n");
    create_keypair(pk, 15, ldevid_crt, &ldevid_crt_len);

    print_hex_string("LDevID PK", pk, PUBLIC_KEY_SIZE);
    print_hex_string("LDevID crt", ldevid_crt, ldevid_crt_len);
    mbedtls_printf("\n");

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

    get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);

    mbedtls_printf("2.1 Getting DICE certificates...\n");
    print_hex_string("LAK crt", certs[0], sizes[0]);
    print_hex_string("SM ECA crt", certs[1], sizes[1]);
    print_hex_string("DevRoot crt", certs[2], sizes[2]);

    mbedtls_printf("\n");
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
    mbedtls_printf("\n[EB]  . Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen((char*)pers))) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");
    */

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[EB]  . Loading the CA root certificate ...");

    ret =  mbedtls_pk_parse_ed25519_key(&ldevid_parsed, (const unsigned char *) pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    if (ret != 0) {
        mbedtls_printf(" failed\n[EB]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n[EB]  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("[EB]  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);

    if ((ret = custom_net_connect(&server_fd, SERVER_NAME,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("[EB]  . Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &ldevid_cert_parsed, &ldevid_parsed)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, "CA")) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_net_send, custom_net_recv, NULL);

    /*
     * 3. Handshake
     */
    mbedtls_printf("[EB]  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Verify the server certificate
     */
    mbedtls_printf("[EB]  . Verifying peer X.509 certificate...");

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

    // Step 3: Retrieve the nonce
    mbedtls_printf("\n2.5 Getting nonce...\n");

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

    mbedtls_printf("\n");
    // Nonce contained in the response
    print_hex_string("nonce", nonce, NONCE_LEN);
    mbedtls_printf("\n");

    // nonce[10] = '\x00';

    // Step 4: Generate CSR
    mbedtls_printf("Generating CSR...\n");

    if((ret = create_csr(pk, nonce, certs, sizes, csr, &csr_len))!=0){
        goto exit;
    }
    
    // Generated CSR
    print_hex_string("CSR", csr, csr_len);
    mbedtls_printf("\n");

    // Step 5: Send CSR to CA
    mbedtls_printf("2.18 Sending CSR...\n");

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
    
    mbedtls_printf(" ...\n\n");

    // Step 7: Close the connection

    mbedtls_printf("Connected using %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_printf("\n");
    
    
    print_hex_string("new LDevID crt", ldevid_ca_cert, ldevid_ca_cert_len);
    mbedtls_printf("\n");

    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    // Parse the received certificate
    mbedtls_x509_crt_init(&cert_gen);
    #if TRUSTED_CHANNEL
    ret = mbedtls_x509_crt_parse_der(&cert_gen, ldevid_ca_cert, ldevid_ca_cert_len);
    #else
    ret = mbedtls_x509_crt_parse(&cert_gen, (const unsigned char*) bob_cert_pem, bob_cert_pem_len);
    #endif
    mbedtls_printf("Parsing new LDevID crt - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_crt_free(&cert_gen);
        goto exit;
    }
    mbedtls_printf("\n");

    ret = test_connection_Alice(&cert_gen, pk);
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
    mbedtls_printf("Storing the certificate in memory...\n");
    if((ret = store_crt(ldevid_ca_cert, ldevid_ca_cert_len)) != 0) {
        mbedtls_printf("Error in storing LDevID_crt\n");
        goto exit;
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[EB] Last error was: %d - %s\n\n", ret, error_buf);
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
    mbedtls_printf("[EB]  > Write to server:");
    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_write returned %d\n\n", ret);
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
    mbedtls_printf("[EB]  < Read from server:");
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
            mbedtls_printf("failed\n[EB]  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\n[EB] EOF\n\n");
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
    mbedtls_pk_context key;
    unsigned char attest_proof[ATTEST_DATA_MAX_LEN];
    size_t attest_proof_len;
    mbedtls_x509write_csr req;
    unsigned char key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    const char subject_name[] = "CN=Bob,O=Enclave-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    unsigned char out_csr[CSR_MAX_LEN];

    int ret = 0;

    mbedtls_printf("2.11 Generating attestation evidence signature...\n");
    crypto_interface(1, nonce, NONCE_LEN, attest_proof, &attest_proof_len, pk);
    print_hex_string("attest_evd_sign", attest_proof, attest_proof_len);
    // mbedtls_printf("\n");

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

    return ret;
}

int test_connection_Alice(mbedtls_x509_crt *crt_Bob, unsigned char *ldevid_pk) {
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t len;
    unsigned char buf[BUF_SIZE];
    mbedtls_net_context server_fd;
    uint32_t flags;
    mbedtls_pk_context ldevid_parsed;
    // const char *pers = "ssl_client1";
    // mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    #if PERFORMANCE_TEST
    ticks_t t_start, t_end, t_diff;
    
    t_start = get_time_inline();
    #endif
    
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
    mbedtls_printf("\n[EB]  . Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen((char*)pers))) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");
    */

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[EB]  . Loading the CA root certificate ...");

    #if TRUSTED_CHANNEL
    ret =  mbedtls_pk_parse_ed25519_key(&ldevid_parsed, (const unsigned char *) ldevid_pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    #else
    ret =  mbedtls_pk_parse_key(&ldevid_parsed, (const unsigned char *) bob_key_pem, bob_key_pem_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    #endif
    if (ret != 0) {
        mbedtls_printf(" failed\n[EB]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit_test;
    }

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n[EB]  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit_test;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("[EB]  . Connecting to tcp/%s/%s...", "Alice", "8062");

    if ((ret = custom_net_connect(&server_fd, SERVER_NAME,
                                   "8062", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("[EB]  . Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit_test;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
    // mbedtls_ssl_conf_cert_profile(&conf,&mbedtls_x509_crt_profile_keystone);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, crt_Bob, &ldevid_parsed)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit_test;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit_test;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, "Alice")) != 0) {
        mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit_test;
    }

    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_net_send, custom_net_recv, NULL);

    /*
     * 3. Handshake
     */
    mbedtls_printf("[EB]  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[EB]  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit_test;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Verify the server certificate
     */
    mbedtls_printf("[EB]  . Verifying peer X.509 certificate...");

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
    len = sprintf((char *) buf, "Hello, I'm Bob!\r\n");

    if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
        goto exit_test;
    }

    // Read the nonce from the response

    if((ret = recv_buf(&ssl, buf, &len, NULL, NULL, get_null))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = len;
        goto exit_test;
    }

    mbedtls_printf("\n");

    mbedtls_printf("Connected using %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_printf("\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit_test:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[EB] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    custom_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&ldevid_parsed);
    // mbedtls_entropy_free(&entropy)

    return exit_code;
}

void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);

    mbedtls_printf("%s:%04d: %s", file, line, str);
}

int get_null(unsigned char *buf, size_t buf_len, unsigned char *empty, size_t *empty_len) {
    return 0;
}
