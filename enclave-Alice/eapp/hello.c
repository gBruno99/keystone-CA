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

#include "eapp/eapp_net.h"

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "certs.h"

#include <stdio.h>
#include <time.h>
#include <string.h>

#define PUBLIC_KEY_SIZE     32
#define PRIVATE_KEY_SIZE    64
#define PARSE_PUBLIC_KEY    0
#define PARSE_PRIVATE_KEY   1
#define CERTS_MAX_LEN       512
#define CSR_SIZE            2048
#define HASH_LEN            64
#define SIG_LEN             64
#define NONCE_LEN           32
#define MDSIZE              64
#define SIGNATURE_SIZE      64
#define ATTEST_DATA_MAXLEN  1024

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define GET_NONCE_REQUEST "GET /nonce HTTP/1.0\r\n\r\n"
#define POST_CSR_REQUEST "POST /csr HTTP/1.0\r\n\r\n"
#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>CA Server - nonce</h2>\r\n" \
    "<p>"

#define HTTP_NONCE_RESPONSE_END \
"</p>\r\n"

#define DEBUG_LEVEL 1

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

int print_hex_string(char* name, unsigned char* value, int size){
  printf("%s: 0x", name);
  for(int i = 0; i< size; i++){
    printf("%02x", value[i]);
  }
  printf("\n");
  printf("%s_len: %d\n", name, size);
  return 0;
}

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
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[2048];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    unsigned char nonce[128];

    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    printf("Current local time and date: %s\n", asctime(timeinfo));
    
    
    // print tci sm and tci enclave
    char report[2048] = {0};
    attest_enclave((void*) report, "test", 5);
    struct report *parsed_report = (struct report*) report;
    print_hex_string("TCI enclave", parsed_report->enclave.hash, 64);
    print_hex_string("TCI sm", parsed_report->sm.hash, 64);
    printf("\n");

    // Client - Step 1: Create LDevID keypair
    printf("Step 1: Generating LDevID...\n\n");
    unsigned char pk[PUBLIC_KEY_SIZE] = {0};
    create_keypair(pk, 15);

    print_hex_string("LDevID PK", pk, PUBLIC_KEY_SIZE);
    printf("\n");

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

    mbedtls_printf("\n[C]  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen((char*)pers))) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[C]  . Loading the CA root certificate ...");
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n[C]  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("[C]  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    if ((ret = custom_net_connect(&server_fd, SERVER_NAME,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("[C]  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("[C]  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("[C]  . Verifying peer X.509 certificate...");

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

    /*
     * 3. Write the GET request
     */
    mbedtls_printf("[C]  > Write to server:");
    fflush(stdout);

    len = sprintf((char *) buf, GET_NONCE_REQUEST);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf("[C] %d bytes written\n\n%s", len, (char *) buf);

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf("[C]  < Read from server:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }

        if (ret < 0) {
            mbedtls_printf("failed\n[C]  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\n[C] EOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        print_hex_string("buf", buf, sizeof(HTTP_NONCE_RESPONSE_START)-1);
        print_hex_string("exp", (unsigned char *) HTTP_NONCE_RESPONSE_START, sizeof(HTTP_NONCE_RESPONSE_START)-1);
        if(memcmp(buf, HTTP_NONCE_RESPONSE_START, sizeof(HTTP_NONCE_RESPONSE_START)-1)!=0) {
            mbedtls_printf("[C] cannot read nonce 1\n\n");
            break;
        }
        memcpy(nonce, buf+sizeof(HTTP_NONCE_RESPONSE_START)-1, NONCE_LEN);
        if(memcmp(buf+sizeof(HTTP_NONCE_RESPONSE_START)-1+NONCE_LEN, HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END))!=0){
            mbedtls_printf("[C] cannot read nonce 2\n\n");
            goto exit;
        }
        print_hex_string("nonce", nonce, NONCE_LEN);
        break;

    } while (1);

    mbedtls_ssl_close_notify(&ssl);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[C] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    custom_net_free(&server_fd);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}

