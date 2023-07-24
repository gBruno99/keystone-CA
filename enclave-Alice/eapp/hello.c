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
#include "certs.h"
#include "printf.h"
#include "custom_functions.h"

// #include <stdio.h>
// #include <time.h>
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
#define PRINT_STRUCTS 0

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define GET_NONCE_REQUEST "GET /nonce HTTP/1.0\r\n\r\n"

#define POST_CSR_REQUEST_START \
    "POST /csr/size HTTP/1.0\r\nContent-Type: application/json\r\n\r\n" \
    "{\"csr_len\": %d, \"csr\": \"0x" 

#define POST_CSR_REQUEST_END \
    "\"}\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"nonce\": \"0x" 

#define HTTP_NONCE_RESPONSE_END \
    "\"}\r\n"

#define HTTP_CERTIFICATE_SIZE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"crt_len\": " 

#define HTTP_CERTIFICATE_SIZE_RESPONSE_END \
    ", "

#define HTTP_CERTIFICATE_RESPONSE_START \
    "\"crt\": \"0x" 

#define HTTP_CERTIFICATE_RESPONSE_END \
    "\"}\r\n"


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

/*
int print_hex_string(char* name, unsigned char* value, int size){
  custom_printf("%s: 0x", name);
  for(int i = 0; i< size; i++){
    custom_printf("%02x", value[i]);
  }
  custom_printf("\n");
  custom_printf("%s_len: %d\n", name, size);
  return 0;
}

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    // fflush((FILE *) ctx);
}

void mbedtls_custom_setup() {
  custom_printf("Setting calloc and free...\n");
  mbedtls_platform_set_calloc_free(calloc, free);
  custom_printf("Setting exit...\n");
  mbedtls_platform_set_exit(custom_exit);
  custom_printf("Setting custom_printf...\n");
  mbedtls_platform_set_printf(custom_printf);
  custom_printf("Setting custom_fprintf...\n");
  mbedtls_platform_set_fprintf(custom_fprintf);
  custom_printf("Setting snprintf...\n");
  mbedtls_platform_set_snprintf(snprintf);
  custom_printf("Setting vsnprintf...\n");
  mbedtls_platform_set_vsnprintf(vsnprintf);
}
*/


int get_crt(unsigned char *buf, unsigned char *crt, int *len);

void custom_exit(int status);

int main(void)
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[2048];
    int ldevid_ca_cert_len = 0;
    unsigned char ldevid_ca_cert[1024] = {0};
    // const char *pers = "ssl_client1";

    // mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    unsigned char nonce[128];

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
    custom_printf("\n");

    /*
    unsigned char *test_malloc = calloc(1, 16);
    if(test_malloc == NULL) {
        custom_printf("Error in malloc\n");
        // fflush(stdout);
    }
    custom_printf("malloc ok\n");
    free(test_malloc);
   
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    custom_printf("Current local time and date: %s\n", asctime(timeinfo));
     */
    
    
    // print tci sm and tci enclave
    char report[2048] = {0};
    custom_printf("[C] Getting TCI values...\n");
    attest_enclave((void*) report, "test", 5);
    struct report *parsed_report = (struct report*) report;
    print_hex_string("TCI enclave", parsed_report->enclave.hash, 64);
    print_hex_string("TCI sm", parsed_report->sm.hash, 64);
    custom_printf("\n");

    // try to read certificate
    // mbedtls_printf("Reading cert in memory...\n");
    ret = read_crt((unsigned char *) ldevid_ca_cert, &ldevid_ca_cert_len);
    if(ret == -1) {
        mbedtls_printf("Error in retrieving crt\n");
    } else {
        print_hex_string("Stored crt", ldevid_ca_cert, ldevid_ca_cert_len);
    }

    // Client - Step 1: Create LDevID keypair
    mbedtls_printf("[C] Generating LDevID...\n\n");
    unsigned char pk[PUBLIC_KEY_SIZE] = {0};
    create_keypair(pk, 15);

    print_hex_string("LDevID PK", pk, PUBLIC_KEY_SIZE);
    mbedtls_printf("\n");

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

    /*
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
    */

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("[C]  . Loading the CA root certificate ...");
    // fflush(stdout);

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
    // fflush(stdout);

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
    // fflush(stdout);
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    // mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_net_send, custom_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("[C]  . Performing the SSL/TLS handshake...");
    // fflush(stdout);

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
    // fflush(stdout);

    // Request to get the nonce
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
    // fflush(stdout);

    // Response containing the nonce
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

        // Get the nonce from the response
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

    // Client - Step 3: Generate CSR
    mbedtls_printf("[C] Generating CSR...\n\n");
    unsigned char *certs[3];
    certs[0] = custom_calloc(1, CERTS_MAX_LEN);
    if(certs[0]==NULL)
        mbedtls_exit(-1);
    certs[1] = custom_calloc(1, CERTS_MAX_LEN);
    if(certs[1]==NULL){
        custom_free(certs[0]);
        mbedtls_exit(-1);
    }
    certs[2] = custom_calloc(1, CERTS_MAX_LEN);
    if(certs[2]==NULL){
        custom_free(certs[0]);
        custom_free(certs[1]);
        mbedtls_exit(-1);
    }
    int sizes[3];
    get_cert_chain(certs[0], certs[1], certs[2], &sizes[0], &sizes[1], &sizes[2]);

    mbedtls_printf("Getting DICE certificates...\n");
    print_hex_string("certs[0]", certs[0], sizes[0]);
    print_hex_string("certs[1]", certs[1], sizes[1]);
    print_hex_string("certs[2]", certs[2], sizes[2]);
    mbedtls_printf("\n");

    ret = 1;
    custom_pk_context key;
    unsigned char attest_proof[512];
    size_t attest_proof_len;
    custom_x509write_csr req;
    unsigned char key_usage = CUSTOM_X509_KU_DIGITAL_SIGNATURE;
    const char subject_name[] = "CN=Client,O=Enclave";

    mbedtls_printf("Generating attestation proof...\n");
    crypto_interface(1, nonce, NONCE_LEN, attest_proof, &attest_proof_len, pk);
    print_hex_string("attest_proof", attest_proof, attest_proof_len);
    mbedtls_printf("\n");

    custom_x509write_csr_init(&req);
    custom_pk_init(&key);

    custom_x509write_csr_set_md_alg(&req, CUSTOM_MD_KEYSTONE_SHA3);
    mbedtls_printf("Setting md algorithm\n");

    ret = custom_x509write_csr_set_key_usage(&req, key_usage);
    mbedtls_printf("Setting key usage - ret: %d\n", ret);

    ret = custom_x509write_csr_set_subject_name(&req, subject_name);
    mbedtls_printf("Setting subject - ret: %d\n", ret);
    
    ret = custom_pk_parse_public_key(&key, pk, PUBLIC_KEY_SIZE, 0);
    mbedtls_printf("Setting pk - ret: %d\n", ret);

    custom_x509write_csr_set_key(&req, &key);
    mbedtls_printf("Setting pk context\n");

    ret = custom_x509write_csr_set_nonce(&req, nonce);
    mbedtls_printf("Setting nonce - ret: %d\n", ret);

    ret = custom_x509write_csr_set_attestation_proof(&req, attest_proof);
    mbedtls_printf("Setting attestation proof - ret: %d\n", ret);

    ret = custom_x509write_csr_set_dice_certs(&req, (unsigned char **)certs, sizes);
    mbedtls_printf("Setting chain of certs - ret: %d\n", ret);

    mbedtls_printf("\n");

    #if PRINT_STRUCTS
    print_custom_x509write_csr("CSR write struct", &req);
    #endif

    unsigned char out_csr[3072];
    int csr_len;

    csr_len = custom_x509write_csr_der(&req, out_csr, 3072, NULL, NULL);
    mbedtls_printf("Writing CSR - ret: %d\n", csr_len);

    unsigned char *gen_csr = out_csr;
    int dif_csr = 3072-csr_len;
    gen_csr += dif_csr;

    print_hex_string("CSR", gen_csr, csr_len);
    mbedtls_printf("\n");

    custom_pk_free(&key);
    custom_x509write_csr_free(&req);

    custom_free(certs[0]);
    custom_free(certs[1]);
    custom_free(certs[2]);

    // Send CSR to CA
    mbedtls_printf("[C]  > Write to server:");
    // fflush(stdout);

    // 1 - Send CSR
    len = sprintf((char *) buf, POST_CSR_REQUEST_START, csr_len);
    memcpy(buf+len-1, gen_csr, csr_len);
    len += csr_len-1;
    memcpy(buf+len, POST_CSR_REQUEST_END, sizeof(POST_CSR_REQUEST_END));
    len += sizeof(POST_CSR_REQUEST_END);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf("[C] %d bytes written\n\n%s", len, (char *) buf);

    /*
    mbedtls_printf("[C]  > Write to server:");
    // fflush(stdout);

    // 2 - Send CSR
    memcpy(buf, POST_CSR_REQUEST_START, sizeof(POST_CSR_REQUEST_START)-1);
    len = sizeof(POST_CSR_REQUEST_START)-1;
    memcpy(buf+len, gen_csr, csr_len);
    len += csr_len;
    memcpy(buf+len, POST_CSR_REQUEST_END, sizeof(POST_CSR_REQUEST_END));
    len += sizeof(POST_CSR_REQUEST_END);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[C]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf("[C] %d bytes written\n\n%s", len, (char *) buf);
    */

    // Get the certificate issued by CA

    // Get crt
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

        // Get Certificate len from the response
        if(get_crt(buf, (unsigned char *) ldevid_ca_cert, &ldevid_ca_cert_len)!=0) {
            mbedtls_printf("[C] error in reading cert len\n");
        }
        //ldevid_ca_cert_len = 345;
        mbedtls_printf("[C] cert_len: %d\n", ldevid_ca_cert_len);
        break;

    } while (1);

    /*
    // Get the certificate
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

        // Read the crt from the response
        if(memcmp(buf, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1)!=0) {
            mbedtls_printf("[C] cannot read certificate\n\n");
            break;
        }
        memcpy(ldevid_ca_cert, buf+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1, ldevid_ca_cert_len);
        if(memcmp(buf+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1+ldevid_ca_cert_len, 
                HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END))!=0){
            mbedtls_printf("[C] cannot read certificate 2\n\n");
            goto exit;
        }
        print_hex_string("certificate", ldevid_ca_cert, ldevid_ca_cert_len);
        break;

    } while (1);
    */

    // Parse the received certificate
    custom_x509_crt cert_gen;
    custom_x509_crt_init(&cert_gen);
    ret = custom_x509_crt_parse_der(&cert_gen, ldevid_ca_cert, ldevid_ca_cert_len);
    mbedtls_printf("Parsing Enclave Certificate - ret: %d\n", ret);
    mbedtls_printf("\n");

    #if PRINT_STRUCTS
    print_custom_x509_cert("Enclave Certificate", cert_gen);
    #endif

    custom_x509_crt_free(&cert_gen);

    mbedtls_printf("Connected using %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

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
    // mbedtls_entropy_free(&entropy);

    // store the certificate
    mbedtls_printf("Storing the certificate in memory...\n");
    ret = store_crt(ldevid_ca_cert, ldevid_ca_cert_len);
    if(ret == -1) {
        mbedtls_printf("Error in storing crt\n");
    }

    mbedtls_exit(exit_code);
}

void custom_exit(int status){
    EAPP_RETURN(status);
}

int get_crt(unsigned char *buf, unsigned char *crt, int *len) {
    int i = 0, j = 0, tmp_len = 0;
    unsigned char start_len[] = HTTP_CERTIFICATE_SIZE_RESPONSE_START;
    unsigned char end_len[] = HTTP_CERTIFICATE_SIZE_RESPONSE_END;
    for(i=0; i<sizeof(HTTP_CERTIFICATE_SIZE_RESPONSE_START)-1; i++){
        if(buf[i] != start_len[i])
            return -1;
    }
    while(buf[i] >= '0' && buf[i] <= '9'){
        tmp_len *= 10;
        tmp_len += buf[i] - '0';
        i++;
    }
    for(j = i; j < i+sizeof(HTTP_CERTIFICATE_SIZE_RESPONSE_END)-1; j++){
        if(buf[j]!=end_len[j-i])
            return -1;
    }
    *len = tmp_len;
    if(memcmp(buf+j, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1)!=0) {
        mbedtls_printf("[C] cannot read certificate\n\n");
        return -1;
    }
    memcpy(crt, buf+j+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1, tmp_len);
    if(memcmp(buf+j+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1+tmp_len, 
            HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END))!=0){
        mbedtls_printf("[C] cannot read certificate 2\n\n");
        return -1;
    }
    return 0;
}

