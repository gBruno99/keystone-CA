/*
 *  SSL server demonstration program
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

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
// #include "certs.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/keystone_ext.h"
#include "mbedtls/print.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

// #include "mbedtls_functions.h"
// #include "ed25519/ed25519.h"
#include "custom_certs.h"
#include "mbedtls/sha3.h"
#include "host/net.h"
// #include "host/ref_certs.h"

#define BUF_SIZE                2048
#define CSR_MAX_LEN             3072
#define CERTS_MAX_LEN           1024
#define NONCE_MAX_LEN           128
#define CN_MAX_LEN              128
#define PK_MAX_LEN              128
#define ATTEST_MAX_LEN          128

#define NET_SUCCESS     -1
#define HANDLER_ERROR   -2
#define GOTO_EXIT       -3
#define GOTO_RESET      -4

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

unsigned char num_crt = 0;

int csr_get_common_name(mbedtls_x509_csr *csr, unsigned char *cn, size_t *cn_len); 

int csr_get_pk(mbedtls_x509_csr *csr, unsigned char *pk, size_t *pk_len);

int csr_get_nonce(mbedtls_x509_csr *csr, unsigned char *nonce, size_t *nonce_len);

int csr_get_attest_evd_sign(mbedtls_x509_csr *csr, unsigned char *attest_evd_sign, size_t *attest_evd_len);

int csr_get_cert(mbedtls_x509_csr *csr, unsigned char *raw_cert, size_t *raw_cert_len, char* crt_subject);

int write_attest_ver_req(mbedtls_x509_csr *csr, unsigned char *buf, size_t *len);

int check_nonce_request(unsigned char *buf, unsigned char *nonce, size_t *nonce_len);

int check_ver_response(unsigned char *buf, unsigned char *tci, size_t *tci_len);

// int get_nonce(unsigned char *buf, unsigned char *nonce, size_t *nonce_len);

int get_csr(unsigned char *buf, unsigned char *csr, size_t *csr_len);

int verify_csr(mbedtls_x509_csr *csr, unsigned char *nonce);

int issue_crt(mbedtls_x509_csr *csr, unsigned char *crt, size_t *crt_len);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, size_t *out_len));

int send_buf_ver(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf_ver(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, size_t *out_len));

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

int main(void)
{
    int ret, err; 
    size_t len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[BUF_SIZE];
    const char *pers = "ssl_server";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context verifier_fd;
    uint32_t flags;
    const char *pers_ver = "ssl_verifier_client";
    mbedtls_entropy_context entropy_ver;
    mbedtls_ctr_drbg_context ctr_drbg_ver;
    mbedtls_ssl_context ssl_ver;
    mbedtls_ssl_config conf_ver;
    mbedtls_x509_crt cert_ver;
    mbedtls_x509_crt cacert_ver;
    mbedtls_pk_context pkey_ver;

    unsigned char nonce[] = {
        0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23,
        0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3
    };
    unsigned char enc_nonce[NONCE_MAX_LEN];
    size_t enc_nonce_len = 0;
    unsigned char recv_csr[CSR_MAX_LEN] = {0};
    size_t csr_len = 0;
    unsigned char crt[CERTS_MAX_LEN] = {0};
    size_t crt_len = 0;
    unsigned char enc_crt[CERTS_MAX_LEN];
    size_t enc_crt_len = 0;
    mbedtls_x509_csr csr;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1. Seed the RNG
     */
    mbedtls_printf("[CA]  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    mbedtls_printf("[CA]  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ref_cert_man,
                                 ref_cert_man_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) ca_key_pem,
                                ca_key_pem_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    mbedtls_printf("[CA]  . Bind on https://localhost:8067/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "8067", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("[CA]  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_cert_profile(&conf,&mbedtls_x509_crt_profile_keystone);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
    err = 0;
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[CA] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("[CA]  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("[CA]  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    // Step 1: Receive request and send nonce
    // Read request
    if((ret = recv_buf(&ssl, buf, &len, NULL, NULL, check_nonce_request))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = -1;
        memcpy(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
        len = sizeof(HTTP_RESPONSE_400);
        if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
            if(ret == GOTO_EXIT){
                ret = len;
                goto exit;
            }
            if(ret == GOTO_RESET){
                ret = len;
                goto reset;
            }
        }
        goto reset;
    }

    /*
    // Send request to get the nonce
    // len = sprintf((char *) buf, GET_NONCE_REQUEST);

    if((ret = send_buf_ver(&ssl_ver, buf, &len))!=NET_SUCCESS){
        err = 2;
        goto exit_ver;
    }

    // Read the nonce from the response

    if((ret = recv_buf_ver(&ssl_ver, buf, &len, nonce, NULL, get_nonce))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = -1;
        err = 2;
        goto exit_ver;
    }
    mbedtls_printf("\n");
    */

    print_hex_string("nonce", nonce, NONCE_LEN);
    mbedtls_printf("\n");
    
    // Write the nonce into the response
    if((ret = mbedtls_base64_encode(enc_nonce, NONCE_MAX_LEN, &enc_nonce_len, nonce, NONCE_LEN))!=0) {
        goto exit;
    }
    len = sprintf((char*) buf, HTTP_NONCE_RESPONSE_START, enc_nonce_len);
    memcpy(buf+len, enc_nonce, enc_nonce_len);
    len += enc_nonce_len;
    memcpy(buf+len, HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END));
    len += sizeof(HTTP_NONCE_RESPONSE_END);

    // Send the response
    if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
        if(ret == GOTO_EXIT){
            ret = len;
            goto exit;
        }
        if(ret == GOTO_RESET){
            ret = len;
            goto reset;
        }
        goto reset;
    }

    // Step 2: Receive CSR and verify it
    // Wait for CSR
    if((ret = recv_buf(&ssl, buf, &len, recv_csr, &csr_len, get_csr))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) {
            ret = -1;
            err = 1;
        } else {
            err = 2;
        }
        goto exit;
    }

    mbedtls_printf("\n");
    print_hex_string("CSR", recv_csr, csr_len);
    mbedtls_printf("\n");
    
    mbedtls_printf("Parsing CSR...\n");
    mbedtls_x509_csr_init(&csr);
    ret = mbedtls_x509_csr_parse_der(&csr, recv_csr, csr_len);
    mbedtls_printf("Parsing CSR - ret: %d\n\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        ret = -1;
        err = 1;
        goto exit;
    }

    // Parse and verify CSR
    if((ret = verify_csr(&csr, nonce))!=0){
        mbedtls_x509_csr_free(&csr);
        ret = -1;
        err = 1;
        goto exit;
    }

    if((ret = write_attest_ver_req(&csr, buf, &len))!=0){
        mbedtls_x509_csr_free(&csr);
        mbedtls_printf("Write verify attestation - ret: %d\n", ret);
        ret = -1;
        err = 2;
        goto exit;
    }

    mbedtls_printf("Connecting to Verifier...\n");
    mbedtls_net_init(&verifier_fd);
    mbedtls_ssl_init(&ssl_ver);
    mbedtls_ssl_config_init(&conf_ver);
    mbedtls_x509_crt_init(&cert_ver);
    mbedtls_x509_crt_init(&cacert_ver);
    mbedtls_pk_init(&pkey_ver);
    mbedtls_ctr_drbg_init(&ctr_drbg_ver);

    mbedtls_printf("\n[CA]  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy_ver);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ver, mbedtls_entropy_func, &entropy_ver,
                                     (const unsigned char *) pers_ver,
                                     strlen(pers_ver))) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit_ver;
    }

    mbedtls_printf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[CA]  . Loading the CA root certificate ...");
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&cert_ver, (const unsigned char *) ver_cert_pem,
                                 ver_cert_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit_ver;
    }

    ret = mbedtls_x509_crt_parse(&cacert_ver, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit_ver;
    }

    ret =  mbedtls_pk_parse_key(&pkey_ver, (const unsigned char *) ca_key_pem,
                                ca_key_pem_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg_ver);
    if (ret != 0) {
        mbedtls_printf(" failed\n[CA]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit_ver;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("[CA]  . Connecting to tcp/%s/%s...", VERIFIER_NAME, VERIFIER_PORT);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&verifier_fd, "localhost",
                                   VERIFIER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit_ver;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("[CA]  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf_ver,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit_ver;
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf_ver, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf_ver, &cert_ver, NULL);
    mbedtls_ssl_conf_rng(&conf_ver, mbedtls_ctr_drbg_random, &ctr_drbg_ver);
    mbedtls_ssl_conf_dbg(&conf_ver, my_debug, stdout);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf_ver, &cacert_ver, &pkey_ver)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit_ver;
    }

    if ((ret = mbedtls_ssl_setup(&ssl_ver, &conf_ver)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit_ver;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl_ver, VERIFIER_NAME)) != 0) {
        mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit_ver;
    }

    mbedtls_ssl_set_bio(&ssl_ver, &verifier_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("[CA]  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl_ver)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit_ver;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("[CA]  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl_ver)) != 0) {
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

    if((ret = send_buf_ver(&ssl_ver, buf, &len))!=NET_SUCCESS){
        err = 2;
        goto exit_ver;
    }

    mbedtls_printf("\n");

    if((ret = recv_buf_ver(&ssl_ver, buf, &len, NULL, NULL, check_ver_response))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) {
            ret = -1;
            err = 1;
        } else {
            err = 2;
        }
        goto exit_ver;
    }


    mbedtls_printf("[CA]  . Closing the connection to Verifier...\n");
    mbedtls_ssl_close_notify(&ssl_ver);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit_ver:
    if(err == 1 || err == 2) {
        switch(err) {
            case 1:
                memcpy(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
                len = sizeof(HTTP_RESPONSE_400);
                break;
            case 2:
                memcpy(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500));
                len = sizeof(HTTP_RESPONSE_500);
                break;
            default:
                break;
        }
        if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
            if(ret == GOTO_EXIT){
                ret = len;
                goto exit;
            }
            if(ret == GOTO_RESET){
                ret = len;
                goto reset;
            }
        }
        err = 0;
    }

    mbedtls_net_free(&verifier_fd);
    mbedtls_x509_crt_free(&cert_ver);
    mbedtls_x509_crt_free(&cacert_ver);
    mbedtls_ssl_free(&ssl_ver);
    mbedtls_pk_free(&pkey_ver);
    mbedtls_ssl_config_free(&conf_ver);
    mbedtls_ctr_drbg_free(&ctr_drbg_ver);
    mbedtls_entropy_free(&entropy_ver);

    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
/*
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[CA] Last error was: %d - %s\n\n", ret, error_buf);
#endif
*/
        mbedtls_x509_csr_free(&csr);
        goto exit;
    }

    // Step 3: Issue LDevID Certificate for Enclave and send it
    mbedtls_printf("\n2.23 Generating Certificate...\n");
    if((ret = issue_crt(&csr, crt, &crt_len)) != 0) {
        mbedtls_x509_csr_free(&csr);
        ret = -1;
        err = 2;
        goto exit;
    }
    mbedtls_x509_csr_free(&csr);

    // Generate response
    // Write certificate len
    if((ret = mbedtls_base64_encode(enc_crt, CERTS_MAX_LEN, &enc_crt_len, crt, crt_len))!=0) {
        err = 2;
        goto exit;
    }
    len = sprintf((char *) buf, HTTP_CERTIFICATE_RESPONSE_START, enc_crt_len);
    // Write ceritificate into response
    memcpy(buf+len, enc_crt, enc_crt_len);
    len += enc_crt_len;
    memcpy(buf+len, HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END));
    len += sizeof(HTTP_CERTIFICATE_RESPONSE_END);

    // Send the response
    if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
        if(ret == GOTO_EXIT){
            ret = len;
            goto exit;
        }
        if(ret == GOTO_RESET){
            ret = len;
            goto reset;
        }
        goto reset;
    }

    mbedtls_printf("[CA]  . Closing the connection to Enclave...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:
if(err == 1 || err == 2) {
        switch(err) {
            case 1:
                memcpy(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
                len = sizeof(HTTP_RESPONSE_400);
                break;
            case 2:
                memcpy(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500));
                len = sizeof(HTTP_RESPONSE_500);
                break;
            default:
                break;
        }
        if((ret = send_buf(&ssl, buf, &len))!=NET_SUCCESS){
            if(ret == GOTO_EXIT){
                ret = len;
                goto exit;
            }
            if(ret == GOTO_RESET){
                ret = len;
                goto reset;
            }
        }
        err = 0;
    }

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[CA] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(ret);
}

int check_nonce_request(unsigned char *buf, unsigned char *nonce, size_t *nonce_len) {
    if(memcmp(buf, GET_NONCE_REQUEST, sizeof(GET_NONCE_REQUEST))!=0) {
        mbedtls_printf("Error in reading nonce request\n\n");
        return -1;
    }
    return 0;
}

/*
int get_nonce(unsigned char *buf, unsigned char *nonce, size_t *nonce_len){
    int ret = 0;
    unsigned char enc_nonce[NONCE_MAX_LEN] = {0};
    size_t enc_nonce_len = 0;
    size_t dec_nonce_len = 0;
    size_t tmp_len = 0;
    int digits = 0;

    if (sscanf((const char *)buf, HTTP_NONCE_RESPONSE_START, &enc_nonce_len) != 1) {
        mbedtls_printf("Error in reading nonce_len\n\n");
        return -1;
    }

    tmp_len = enc_nonce_len;
    while(tmp_len > 0) { 
        digits++;
        tmp_len/=10;
    } 
    digits -= 3;

    // Read CSR from the request
    memcpy(enc_nonce, buf + sizeof(HTTP_NONCE_RESPONSE_START)-1+digits, enc_nonce_len);
    
    if (memcmp(buf + sizeof(HTTP_NONCE_RESPONSE_START) + digits + enc_nonce_len -1 , HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END)) != 0) {
        mbedtls_printf("Cannot read nonce 2\n\n");
        return -1;
    }

    ret = mbedtls_base64_decode(nonce, NONCE_MAX_LEN, &dec_nonce_len, enc_nonce, enc_nonce_len);
    return ret || (dec_nonce_len != NONCE_LEN);
}
*/

int get_csr(unsigned char *buf, unsigned char *csr, size_t *csr_len) {
    unsigned char enc_csr[CSR_MAX_LEN];
    size_t enc_csr_len;
    size_t tmp_len = 0;
    int digits = 0;
    // Read csr_len from the request
    if (sscanf((const char *)buf, POST_CSR_REQUEST_START, &enc_csr_len) != 1) {
        mbedtls_printf("Error in reading csr_len\n\n");
        return -1;
    }

    tmp_len = enc_csr_len;
    while(tmp_len > 0) { 
        digits++;
        tmp_len/=10;
    } 
    digits -= 3;

    // Read CSR from the request
    memcpy(enc_csr, buf + sizeof(POST_CSR_REQUEST_START)-1+digits, enc_csr_len);
    
    if (memcmp(buf + sizeof(POST_CSR_REQUEST_START) + digits + enc_csr_len -1 , POST_CSR_REQUEST_END, sizeof(POST_CSR_REQUEST_END)) != 0) {
        mbedtls_printf("Cannot read csr 2\n\n");
        return -1;
    }
    return mbedtls_base64_decode(csr, CSR_MAX_LEN, csr_len, enc_csr, enc_csr_len);
}

int verify_csr(mbedtls_x509_csr *csr, unsigned char *nonce) {
    int ret;
    unsigned char csr_hash[KEYSTONE_HASH_MAX_SIZE] = {0};
    uint32_t flags = 0;
    mbedtls_x509_crt trusted_certs;
    // unsigned char verification_pk[PUBLIC_KEY_SIZE] = {0};
    // unsigned char reference_tci[KEYSTONE_HASH_MAX_SIZE] = {0};
    // unsigned char fin_hash[KEYSTONE_HASH_MAX_SIZE] = {0};
    // sha3_ctx_t ctx_hash;
    // mbedtls_pk_context key;

    // Verify CSR signature
    mbedtls_printf("2.19 Verifying CSR...\n");
    ret = mbedtls_md(mbedtls_md_info_from_type(csr->MBEDTLS_PRIVATE(sig_md)), csr->cri.p, csr->cri.len, csr_hash);
    mbedtls_printf("Hashing CSR - ret: %d\n", ret);
    if(ret != 0) {
        return 2;
    }
    #if PRINT_STRUCTS
    print_hex_string("Hash CSR", csr_hash, KEYSTONE_HASH_MAX_SIZE);
    #endif
    ret = mbedtls_pk_verify_ext(csr->MBEDTLS_PRIVATE(sig_pk), csr->MBEDTLS_PRIVATE(sig_opts), &(csr->pk), csr->MBEDTLS_PRIVATE(sig_md), csr_hash, KEYSTONE_HASH_MAX_SIZE, csr->MBEDTLS_PRIVATE(sig).p, csr->MBEDTLS_PRIVATE(sig).len);
    mbedtls_printf("Verify CSR signature - ret: %d\n", ret);
    if(ret != 0) {
        return 3;
    }

    // Verify nonces equality
    ret = csr->nonce.len != NONCE_LEN;
    mbedtls_printf("Verify nonce len - ret: %d\n", ret);
    if(ret != 0) {
        return 4;
    }
    ret = memcmp(csr->nonce.p, nonce, NONCE_LEN);
    mbedtls_printf("Verify nonce value - ret: %d\n", ret);
    if(ret != 0) {
        return 5;
    }

    // Parse trusted certificate
    mbedtls_x509_crt_init(&trusted_certs);
    ret = mbedtls_x509_crt_parse_der(&trusted_certs, ref_cert_man, ref_cert_man_len);
    mbedtls_printf("Parsing Trusted Certificate - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_mbedtls_x509_cert("Trusted Certificate", trusted_certs);
    #endif
    if(ret != 0) {
        mbedtls_x509_crt_free(&trusted_certs);
        return 6;
    }

    // cert_chain.hash.p[15] = 0x56; // Used to break verification

    //  Verify chain of certificates
    ret = mbedtls_x509_crt_verify_with_profile(&(csr->cert_chain), &trusted_certs, NULL, &mbedtls_x509_crt_profile_keystone, NULL, &flags, NULL, NULL);
    mbedtls_printf("Verifying Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
    mbedtls_x509_crt_free(&trusted_certs);
    if(ret != 0) {
        return 7;
    }

    /*
    // Verify attestation proof
    // Get SM public key
    ret = getAttestationPublicKey(csr, verification_pk);
    mbedtls_printf("Getting SM PK - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("SM PK", verification_pk, PUBLIC_KEY_SIZE);
    #endif
    if(ret != 0) {
        return 8;
    }

    // Get enclave reference TCI
    ret = getReferenceTCI(csr, reference_tci);
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        return 9;
    }

    // Compute reference attestation proof
    sha3_init(&ctx_hash, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, nonce, NONCE_LEN);
    sha3_update(&ctx_hash, reference_tci, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, mbedtls_pk_ed25519(csr->pk)->pub_key, PUBLIC_KEY_SIZE);
    sha3_final(fin_hash, &ctx_hash);
    #if PRINT_STRUCTS
    print_hex_string("fin_hash", fin_hash, KEYSTONE_HASH_MAX_SIZE);
    #endif

    // Verify signature of the attestation proof
    mbedtls_pk_init(&key);
    ret = mbedtls_pk_parse_ed25519_key(&key, verification_pk, PUBLIC_KEY_SIZE, 0);
    mbedtls_printf("Parsing SM PK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_pk_free(&key);
        return 10;
    }

    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_ED25519, NULL, &key, MBEDTLS_MD_KEYSTONE_SHA3, fin_hash, KEYSTONE_HASH_MAX_SIZE, csr->attestation_proof.p, csr->attestation_proof.len);
    mbedtls_printf("Verifying attestation proof - ret: %d\n", ret);
    mbedtls_pk_free(&key);
    if(ret != 0) {
        return 11;
    }
    */

    mbedtls_printf("\n");
    fflush(stdout);
    return 0;
}

int issue_crt(mbedtls_x509_csr *csr, unsigned char *crt, size_t *crt_len) {
    int ret;
    // mbedtls_x509_csr csr;
    mbedtls_x509write_cert cert_encl;
    mbedtls_pk_context subj_key;
    mbedtls_pk_context issu_key;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "issuing_cert";
    unsigned char serial[] = {0xAB, 0xAB, 0xAB};
    unsigned char reference_tci[KEYSTONE_HASH_MAX_SIZE] = {0};
    unsigned char cert_der[CERTS_MAX_LEN];
    int effe_len_cert_der;
    size_t len_cert_der_tot = CERTS_MAX_LEN;
    unsigned char *cert_real;
    int dif;

    serial[2] = num_crt;
    num_crt++;
    print_hex_string("serial", serial, 3);

    // Get enclave reference TCI
    ret = getReferenceTCI(csr, reference_tci);
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        return 9;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_printf("Seeding RNG - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return 2;
    }
    // Set certificate fields
    mbedtls_x509write_crt_init(&cert_encl);

    mbedtls_printf("Setting Certificate fields...\n");
    ret = mbedtls_x509write_crt_set_issuer_name(&cert_encl, "O=Certificate Authority");
    mbedtls_printf("Setting issuer - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        return 2;
    }
    
    ret = mbedtls_x509write_crt_set_subject_name(&cert_encl, "CN=Client1,O=Certificate Authority");
    mbedtls_printf("Setting subject - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        return 3;
    }

    mbedtls_pk_init(&subj_key);
    mbedtls_pk_init(&issu_key);

    ret = mbedtls_pk_parse_key(&issu_key, (const unsigned char *) ca_key_pem,
                                ca_key_pem_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_printf("Parsing issuer key - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 4;
    }

    ret = mbedtls_pk_parse_ed25519_key(&subj_key, mbedtls_pk_ed25519(csr->pk)->pub_key, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing subject PK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 6;
    }

    mbedtls_x509write_crt_set_subject_key(&cert_encl, &subj_key);
    mbedtls_printf("Setting subject key\n");

    mbedtls_x509write_crt_set_issuer_key(&cert_encl, &issu_key);
    mbedtls_printf("Setting issuer keys\n");
    
    ret = mbedtls_x509write_crt_set_serial_raw(&cert_encl, serial, 3);
    mbedtls_printf("Setting serial - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 7;
    }
    
    mbedtls_x509write_crt_set_md_alg(&cert_encl, MBEDTLS_MD_SHA512);
    mbedtls_printf("Setting md algorithm\n");
    
    ret = mbedtls_x509write_crt_set_validity(&cert_encl, "20230101000000", "20240101000000");
    mbedtls_printf("Setting validity - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 8;
    }

    ret = mbedtls_x509write_crt_set_extension(&cert_encl, MBEDTLS_OID_TCI, 3, 0, reference_tci, KEYSTONE_HASH_MAX_SIZE);
    mbedtls_printf("Setting TCI - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 9;
    }

    mbedtls_printf("\n");

    // Writing certificate
    ret = mbedtls_x509write_crt_der(&cert_encl, cert_der, len_cert_der_tot, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_printf("Writing Enclave Certificate - ret: %d\n", ret);
    if(ret <= 0) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 10;
    }

    effe_len_cert_der = ret;
    cert_real = cert_der;
    dif  = CERTS_MAX_LEN-effe_len_cert_der;
    cert_real += dif;

    memcpy(crt, cert_real, effe_len_cert_der);
    *crt_len = effe_len_cert_der;

    print_hex_string("Enclave Certificate", cert_real, effe_len_cert_der);
    mbedtls_printf("\n");
    fflush(stdout);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&issu_key);
    mbedtls_pk_free(&subj_key);
    mbedtls_x509write_crt_free(&cert_encl);
    return 0;
}

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len) {
    int ret;
    mbedtls_printf("[CA]  > Write to client:");
    fflush(stdout);

    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[CA]  ! peer closed the connection\n\n");
            *len = ret;
            return GOTO_RESET;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_write returned %d\n\n", ret);
            *len = ret;
            return GOTO_EXIT;
        }
    }

    *len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", *len, (char *) buf);
    return NET_SUCCESS;
}

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, size_t *out_len)) {
    int ret;
    mbedtls_printf("[CA]  < Read from client:");
    fflush(stdout);
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
            if(handler(buf, data, data_len)!=0) {
                return HANDLER_ERROR;
            }
            ret = NET_SUCCESS;
            break;
        }
    } while (1);
    return ret;
}

int send_buf_ver(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len){
    int ret;
    mbedtls_printf("[CA]  > Write to server:");
    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[CA]  ! mbedtls_ssl_write returned %d\n\n", ret);
            return ret;
        }
    }

    *len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", *len, (char *) buf);
    return NET_SUCCESS;
}

// buf must be BUF_SIZE byte long
int recv_buf_ver(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, size_t *out_len)){
    int ret;
    mbedtls_printf("[CA]  < Read from server:");
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
            mbedtls_printf("failed\n[CA]  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\n[CA] EOF\n\n");
            break;
        }

        *len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", *len, (char *) buf);

        // Get the data from the response
        if(handler(buf, data, data_len) != 0){
            return HANDLER_ERROR;
        } 
        ret = NET_SUCCESS;
        break;

    } while (1);
    return ret;
}

int check_ver_response(unsigned char *buf, unsigned char *tci, size_t *tci_len) {
    int msg = -1;
    if(memcmp(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400))==0) {
        mbedtls_printf("\nError in validating attestation\n\n");
        msg = -2;
    } else {
        if(memcmp(buf, HTTP_RESPONSE_200, sizeof(HTTP_RESPONSE_200))==0) {
            mbedtls_printf("\nValidation ok\n\n");
            msg = 0;
        }
    }
    return msg;
}

int write_attest_ver_req(mbedtls_x509_csr *csr, unsigned char *buf, size_t *len) {
    unsigned char csr_cn[CN_MAX_LEN];
    unsigned char csr_pk[PK_MAX_LEN];
    unsigned char csr_nonce[NONCE_MAX_LEN];  
    unsigned char csr_attest_sig[ATTEST_MAX_LEN]; 
    unsigned char csr_cert_lak[CERTS_MAX_LEN]; 
    unsigned char csr_cert_root[CERTS_MAX_LEN];
    unsigned char csr_cert_sm[CERTS_MAX_LEN];
    size_t csr_cn_len;
    size_t csr_pk_len;
    size_t csr_nonce_len;
    size_t csr_attest_sig_len;
    size_t csr_cert_lak_len;
    size_t csr_cert_root_len;
    size_t csr_cert_sm_len;

    if(csr_get_common_name(csr, csr_cn, &csr_cn_len) != 0) {
        return 1;
    }

    if(csr_get_pk(csr, csr_pk, &csr_pk_len) != 0) {
        return 2;
    }

    if(csr_get_nonce(csr, csr_nonce, &csr_nonce_len) != 0) {
        return 3;
    }

    if(csr_get_attest_evd_sign(csr, csr_attest_sig, &csr_attest_sig_len) != 0) {
        return 4;
    }

    if(csr_get_cert(csr, csr_cert_root, &csr_cert_root_len, "Root of Trust") != 0) {
        return 5;
    }

    if(csr_get_cert(csr, csr_cert_sm, &csr_cert_sm_len, "Security Monitor") != 0) {
        return 5;
    }

    if(csr_get_cert(csr, csr_cert_lak, &csr_cert_lak_len, "Enclave") != 0) {
        return 5;
    }

    *len = sprintf((char*) buf, POST_ATTESTATION_REQUEST, csr_cn, csr_pk, csr_nonce, csr_attest_sig, csr_cert_root, csr_cert_sm, csr_cert_lak);
    return *len == -1;
}

int csr_get_common_name(mbedtls_x509_csr *csr, unsigned char *cn, size_t *cn_len) {
    mbedtls_x509_name *subject = &(csr->subject);
    while(subject != NULL && strncmp((char*) subject->oid.p, MBEDTLS_OID_AT_CN, subject->oid.len)!=0)
        subject = subject->next;
    if(subject == NULL) {
        return -1;
    }
    *cn_len = subject->val.len;
    strncpy((char*) cn, (char*) subject->val.p, *cn_len);
    cn[*cn_len] = '\0';
    // mbedtls_printf("%lu: %s\n", *cn_len, cn);
    return 0;
}

int csr_get_pk(mbedtls_x509_csr *csr, unsigned char *pk, size_t *pk_len) {
    if(mbedtls_pk_can_do(&(csr->pk), MBEDTLS_PK_ED25519)) {
        strcpy((char*) pk, (char*) mbedtls_pk_ed25519(csr->pk)->pub_key);
        return mbedtls_base64_encode(pk, PK_MAX_LEN, pk_len, mbedtls_pk_ed25519(csr->pk)->pub_key, PUBLIC_KEY_SIZE);
    }
    return -1;
}

int csr_get_nonce(mbedtls_x509_csr *csr, unsigned char *nonce, size_t *nonce_len) {
    return mbedtls_base64_encode(nonce, NONCE_MAX_LEN, nonce_len, csr->nonce.p, NONCE_LEN);
}

int csr_get_attest_evd_sign(mbedtls_x509_csr *csr, unsigned char *attest_evd_sign, size_t *attest_evd_len) {
    return mbedtls_base64_encode(attest_evd_sign, ATTEST_MAX_LEN, attest_evd_len, csr->attestation_proof.p, ATTESTATION_PROOF_LEN);
}

int csr_get_cert(mbedtls_x509_csr *csr, unsigned char *raw_cert, size_t *raw_cert_len, char* crt_subject) {
    mbedtls_x509_crt *crt = &(csr->cert_chain);
    while(crt != NULL && strncmp((char*) crt->subject.val.p, crt_subject, strlen(crt_subject))!=0)
        crt = crt->next;
    if(crt == NULL)
        return -1;
    return mbedtls_base64_encode(raw_cert, CERTS_MAX_LEN, raw_cert_len, crt->raw.p, crt->raw.len);
}
