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
#define RESPONSE_MAX_LEN        128
#define CN_MAX_LEN              128
#define PK_MAX_LEN              128
#define ATTEST_MAX_LEN          128

#define NET_SUCCESS     1
#define HANDLER_ERROR   2
#define GOTO_EXIT       3
#define GOTO_RESET      4

/*
unsigned char ref_nonce[] = {
        0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23,
        0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3
    };
*/

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

// int check_nonce_request(unsigned char *buf, unsigned char *nonce, size_t *nonce_len);

int verify_attest_evidence(unsigned char *buf, unsigned char *resp, size_t *resp_len);

int get_encoded_field(unsigned char *buf, size_t *index, char *format, unsigned char *output, size_t *outlen, int encoded);

// int get_csr(unsigned char *buf, unsigned char *csr, size_t *csr_len);

// int verify_csr(unsigned char *recv_csr, size_t csr_len);

// int issue_crt(unsigned char *recv_csr, size_t csr_len, unsigned char *crt, size_t *crt_len);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
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
    uint32_t flags; 
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

    // unsigned char enc_nonce[NONCE_MAX_LEN];
    // size_t enc_nonce_len = 0;
    unsigned char resp[RESPONSE_MAX_LEN];
    size_t resp_len;
    /*
    unsigned char recv_csr[CSR_MAX_LEN] = {0};
    size_t csr_len = 0;
    unsigned char crt[CERTS_MAX_LEN] = {0};
    size_t crt_len = 0;
    unsigned char enc_crt[CERTS_MAX_LEN];
    size_t enc_crt_len = 0;
    */

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
    mbedtls_printf("[Ver]  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    mbedtls_printf("[Ver]  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) ver_cert_pem,
                                 ver_cert_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[Ver]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_cert_pem,
                                 ca_cert_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[Ver]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) ver_key_pem,
                                ver_key_pem_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" failed\n[Ver]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    mbedtls_printf("[Ver]  . Bind on https://localhost:8068/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "8068", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("[Ver]  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
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
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
    err = 0;
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[Ver] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("[Ver]  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n[Ver]  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("[Ver]  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Verify the client certificate
     */
    mbedtls_printf("[Ver]  . Verifying peer X.509 certificate...");

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
    // Step 1: Receive request and send nonce
    // Read request
    if((ret = recv_buf(&ssl, buf, &len, NULL, NULL, check_nonce_request))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) ret = -1;
        err = 1;
        memcpy(buf, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
        len = sizeof(HTTP_RESPONSE_400);
    } else {
        // Write the nonce into the response
        if((ret = mbedtls_base64_encode(enc_nonce, NONCE_MAX_LEN, &enc_nonce_len, ref_nonce, NONCE_LEN))!=0) {
            err = 2;
            memcpy(buf, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500));
            len = sizeof(HTTP_RESPONSE_500);
        } else {
            len = sprintf((char*) buf, HTTP_NONCE_RESPONSE_START, enc_nonce_len);
            memcpy(buf+len, enc_nonce, enc_nonce_len);
            len += enc_nonce_len;
            memcpy(buf+len, HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END));
            len += sizeof(HTTP_NONCE_RESPONSE_END);
        }
    }

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

    switch(err) {
        case 1:
            ret = -1;
            goto reset;
        case 2:
            ret = -1;
            goto exit;
        default:
            break;
    }
    */

    // Step 1: Receive attestation message and verify it
    // Wait for attestation message
    if((ret = recv_buf(&ssl, buf, &len, resp, &resp_len, verify_attest_evidence))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) {
            ret = len;
            err = 1;
            memcpy(resp, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
            resp_len = sizeof(HTTP_RESPONSE_400);
        } else {
            goto reset;
        }
    }

    if((ret = send_buf(&ssl, resp, &resp_len))!=NET_SUCCESS){
        if(ret == GOTO_EXIT){
            ret = resp_len;
            goto exit;
        }
        if(ret == GOTO_RESET){
            ret = resp_len;
            goto reset;
        }
        goto reset;
    }

    switch(err) {
        case 1:
            goto reset;
        case 2:
            goto exit;
        default:
            break;
    }

/*
    mbedtls_printf("\n");
    print_hex_string("[Ver] CSR", recv_csr, csr_len);
    mbedtls_printf("\n");
    
    // Parse and verify CSR
    if((ret = verify_csr(recv_csr, csr_len, ref_nonce))!=0){
        ret = -1;
        goto exit;
    }

    // Step 3: Issue LDevID Certificate for Enclave and send it
    mbedtls_printf("[Ver] Generating Certificate...\n\n");
    if((ret = issue_crt(recv_csr, csr_len, crt, &crt_len)) != 0) {
        ret = -1;
        goto exit;
    }

    // Generate response
    // Write certificate len
    if((ret = mbedtls_base64_encode(enc_crt, CERTS_MAX_LEN, &enc_crt_len, crt, crt_len))!=0) {
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
*/

    mbedtls_printf("[Ver]  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[Ver] Last error was: %d - %s\n\n", ret, error_buf);
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

/*
int check_nonce_request(unsigned char *buf, unsigned char *nonce, size_t *nonce_len) {
    if(memcmp(buf, GET_NONCE_REQUEST, sizeof(GET_NONCE_REQUEST))!=0) {
        mbedtls_printf("Error in reading nonce request\n\n");
        return -1;
    }
    return 0;
}

int get_csr(unsigned char *buf, unsigned char *csr, size_t *csr_len) {
    unsigned char enc_csr[CSR_MAX_LEN];
    size_t enc_csr_len;
    size_t tmp_len = 0;
    int digits = 0;
    // Read csr_len from the request
    if (sscanf((const char *)buf, POST_CSR_REQUEST_START, &enc_csr_len) != 1) {
        mbedtls_printf("Error in reading CSR_len\n\n");
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
        mbedtls_printf("Cannot read CSR 2\n\n");
        return -1;
    }
    return mbedtls_base64_decode(csr, CSR_MAX_LEN, csr_len, enc_csr, enc_csr_len);
}

int verify_csr(unsigned char *recv_csr, size_t csr_len) {
    int ret;
    mbedtls_x509_csr csr;
    unsigned char csr_hash[KEYSTONE_HASH_MAX_SIZE] = {0};
    uint32_t flags = 0;
    mbedtls_x509_crt trusted_certs;
    unsigned char verification_pk[PUBLIC_KEY_SIZE] = {0};
    unsigned char reference_tci[KEYSTONE_HASH_MAX_SIZE] = {0};
    unsigned char fin_hash[KEYSTONE_HASH_MAX_SIZE] = {0};
    sha3_ctx_t ctx_hash;
    mbedtls_pk_context key;

    // Parse CSR
    mbedtls_printf("Parsing CSR...\n");
    mbedtls_x509_csr_init(&csr);
    ret = mbedtls_x509_csr_parse_der(&csr, recv_csr, csr_len);
    mbedtls_printf("Parsing CSR - ret: %d\n\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 1;
    }

    // Verify CSR signature
    mbedtls_printf("Verifying CSR...\n");
    ret = mbedtls_md(mbedtls_md_info_from_type(csr.MBEDTLS_PRIVATE(sig_md)), csr.cri.p, csr.cri.len, csr_hash);
    mbedtls_printf("Hashing CSR- ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 2;
    }
    #if PRINT_STRUCTS
    print_hex_string("Hash CSR", csr_hash, KEYSTONE_HASH_MAX_SIZE);
    #endif
    ret = mbedtls_pk_verify_ext(csr.MBEDTLS_PRIVATE(sig_pk), csr.MBEDTLS_PRIVATE(sig_opts), &(csr.pk), csr.MBEDTLS_PRIVATE(sig_md), csr_hash, KEYSTONE_HASH_MAX_SIZE, csr.MBEDTLS_PRIVATE(sig).p, csr.MBEDTLS_PRIVATE(sig).len);
    mbedtls_printf("Verifying CSR signature - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 3;
    }

    // Verify nonces equality
    ret = csr.nonce.len != NONCE_LEN;
    mbedtls_printf("Verify nonce len - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 4;
    }
    ret = memcmp(csr.nonce.p, ref_nonce, NONCE_LEN);
    mbedtls_printf("Verify nonce value - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
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
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509_crt_free(&trusted_certs);
        return 6;
    }

    // cert_chain.hash.p[15] = 0x56; // Used to break verification

    //  Verify chain of certificates
    ret = mbedtls_x509_crt_verify_with_profile(&(csr.cert_chain), &trusted_certs, NULL, &mbedtls_x509_crt_profile_keystone, NULL, &flags, NULL, NULL);
    mbedtls_printf("Verifing Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
    mbedtls_x509_crt_free(&trusted_certs);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 7;
    }

    // Verify attestation proof
    // Get SM public key
    ret = getAttestationPublicKey(&(csr.cert_chain), verification_pk);
    mbedtls_printf("Getting SM PK - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("SM PK", verification_pk, PUBLIC_KEY_SIZE);
    #endif
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 8;
    }

    // Get enclave reference TCI
    ret = getReferenceTCI(&csr, reference_tci);
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 9;
    }

    // Compute reference attestation proof
    sha3_init(&ctx_hash, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, ref_nonce, NONCE_LEN);
    sha3_update(&ctx_hash, reference_tci, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, mbedtls_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE);
    sha3_final(fin_hash, &ctx_hash);
    #if PRINT_STRUCTS
    print_hex_string("fin_hash", fin_hash, KEYSTONE_HASH_MAX_SIZE);
    #endif

    // Verify signature of the attestation proof
    mbedtls_pk_init(&key);
    ret = mbedtls_pk_parse_ed25519_key(&key, verification_pk, PUBLIC_KEY_SIZE, 0);
    mbedtls_printf("Parsing SM PK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_pk_free(&key);
        return 10;
    }

    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_ED25519, NULL, &key, MBEDTLS_MD_KEYSTONE_SHA3, fin_hash, KEYSTONE_HASH_MAX_SIZE, csr.attestation_proof.p, csr.attestation_proof.len);
    mbedtls_printf("Verifying attestation evidence signature - ret: %d\n", ret);
    mbedtls_pk_free(&key);
    mbedtls_x509_csr_free(&csr);
    if(ret != 0) {
        return 11;
    }

    mbedtls_printf("\n");
    fflush(stdout);
    return 0;
}

int issue_crt(unsigned char *recv_csr, size_t csr_len, unsigned char *crt, size_t *crt_len) {
    int ret;
    mbedtls_x509_csr csr;
    mbedtls_x509write_cert cert_encl;
    mbedtls_pk_context subj_key;
    mbedtls_pk_context issu_key;
    unsigned char serial[] = {0xAB, 0xAB, 0xAB};
    unsigned char reference_tci[KEYSTONE_HASH_MAX_SIZE] = {0};
    unsigned char cert_der[CERTS_MAX_LEN];
    int effe_len_cert_der;
    size_t len_cert_der_tot = CERTS_MAX_LEN;
    unsigned char *cert_real;
    int dif;

    // Parse CSR
    mbedtls_printf("Parsing CSR...\n");
    mbedtls_x509_csr_init(&csr);
    ret = mbedtls_x509_csr_parse_der(&csr, recv_csr, csr_len);
    mbedtls_printf("Parsing CSR - ret: %d\n\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 1;
    }

    // Get enclave reference TCI
    ret = getReferenceTCI(&csr, reference_tci);
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 9;
    }

    // Set certificate fields
    mbedtls_x509write_crt_init(&cert_encl);

    mbedtls_printf("Setting Certificate fields...\n");
    ret = mbedtls_x509write_crt_set_issuer_name(&cert_encl, "O=Certificate Authority");
    mbedtls_printf("Setting issuer - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        return 2;
    }
    
    ret = mbedtls_x509write_crt_set_subject_name(&cert_encl, "CN=Client1,O=Certificate Authority");
    mbedtls_printf("Setting subject - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        return 3;
    }

    mbedtls_pk_init(&subj_key);
    mbedtls_pk_init(&issu_key);
    
    ret = mbedtls_pk_parse_ed25519_key(&issu_key, sanctum_ca_private_key, PRIVATE_KEY_SIZE, ED25519_PARSE_PRIVATE_KEY);
    mbedtls_printf("Parsing issuer PK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 4;
    }

    ret = mbedtls_pk_parse_ed25519_key(&issu_key, sanctum_ca_public_key, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing issuer SK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 5;
    }

    ret = mbedtls_pk_parse_ed25519_key(&subj_key, mbedtls_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing subject PK - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
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
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 7;
    }
    
    mbedtls_x509write_crt_set_md_alg(&cert_encl, MBEDTLS_MD_KEYSTONE_SHA3);
    mbedtls_printf("Setting md algorithm\n");
    
    ret = mbedtls_x509write_crt_set_validity(&cert_encl, "20230101000000", "20240101000000");
    mbedtls_printf("Setting validity - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 8;
    }

    ret = mbedtls_x509write_crt_set_extension(&cert_encl, MBEDTLS_OID_TCI, 3, 0, reference_tci, KEYSTONE_HASH_MAX_SIZE);
    mbedtls_printf("Setting TCI - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 9;
    }

    mbedtls_printf("\n");

    // Writing certificate
    ret = mbedtls_x509write_crt_der(&cert_encl, cert_der, len_cert_der_tot, NULL, NULL);
    mbedtls_printf("Writing Enclave Certificate - ret: %d\n", ret);
    if(ret <= 0) {
        mbedtls_x509_csr_free(&csr);
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

    mbedtls_pk_free(&issu_key);
    mbedtls_pk_free(&subj_key);
    mbedtls_x509write_crt_free(&cert_encl);
    mbedtls_x509_csr_free(&csr);
    return 0;
}
*/

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len) {
    int ret;
    mbedtls_printf("[Ver]  > Write to client:");
    fflush(stdout);

    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[Ver]  ! peer closed the connection\n\n");
            *len = ret;
            return GOTO_RESET;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[Ver]  ! mbedtls_ssl_write returned %d\n\n", ret);
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
    mbedtls_printf("[Ver]  < Read from client:");
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
            if((ret = handler(buf, data, data_len))!=0) {
                *len = ret;
                return HANDLER_ERROR;
            }
            ret = NET_SUCCESS;
            break;
        }
    } while (1);
    return ret;
}

int verify_attest_evidence(unsigned char *buf, unsigned char *resp, size_t *resp_len) {
    int ret = 0;
    size_t len = 0;
    unsigned char cn[CN_MAX_LEN] = {0};
    size_t cn_len = CN_MAX_LEN;
    unsigned char pk[PUBLIC_KEY_SIZE] = {0};
    size_t pk_len = PUBLIC_KEY_SIZE;
    unsigned char nonce[NONCE_LEN] = {0};
    size_t nonce_len = NONCE_LEN;
    unsigned char attest_evd[ATTESTATION_PROOF_LEN] = {0};
    size_t attest_evd_len = ATTESTATION_PROOF_LEN;
    unsigned char tmp_crt[CERTS_MAX_LEN] = {0};
    size_t tmp_crt_len = CERTS_MAX_LEN;

    mbedtls_x509_crt dice_certs;
    mbedtls_x509_crt trusted_certs;
    unsigned char verification_pk[PUBLIC_KEY_SIZE] = {0};
    unsigned char reference_tci[KEYSTONE_HASH_MAX_SIZE] = {0};
    unsigned char fin_hash[KEYSTONE_HASH_MAX_SIZE] = {0};
    sha3_ctx_t ctx_hash;
    mbedtls_pk_context key;
    uint32_t flags = 0;
    size_t body_len = 0;
    size_t tmp_len = 0;
    int digits = 0;

    mbedtls_x509_crt_init(&dice_certs);
    mbedtls_x509_crt_init(&trusted_certs);
    mbedtls_pk_init(&key);

    mbedtls_printf("\n2.21 Reading attestation message...\n");

    if (sscanf((const char *)buf, POST_ATTESTATION_REQUEST_START, &body_len) != 1) {
        ret = -1;
        goto gen_resp;
    }

    mbedtls_printf("body_len: %lu\n", body_len);

    tmp_len = body_len;
    while(tmp_len > 0) { 
        digits++;
        tmp_len/=10;
    } 
    digits -= 3;
    len = sizeof(POST_ATTESTATION_REQUEST_START)-1+digits;

    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_SUBJECT, cn, &cn_len, 0)) != 0) {
        goto gen_resp;
    }
    mbedtls_printf("CN: %s, %lu\n", cn, cn_len);
       
    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_PK, pk, &pk_len, 1)) != 0) {
        goto gen_resp;
    }
    print_hex_string("PK", pk, pk_len);
    
    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_NONCE, nonce, &nonce_len, 1)) != 0) {
        goto gen_resp;
    }
    print_hex_string("nonce", nonce, nonce_len);

    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_ATTEST_SIG, attest_evd, &attest_evd_len, 1)) != 0) {
        goto gen_resp;
    }
    print_hex_string("attest_evd_sign", attest_evd, attest_evd_len);

    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_CRT_DEVROOT, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        goto gen_resp;
    }
    print_hex_string("DevRoot crt", tmp_crt, tmp_crt_len);
    tmp_crt_len = CERTS_MAX_LEN;

    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_CRT_SM, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        goto gen_resp;
    }
    print_hex_string("SM ECA crt", tmp_crt, tmp_crt_len);
    tmp_crt_len = CERTS_MAX_LEN;

    if((ret = get_encoded_field(buf, &len, POST_ATTESTATION_REQUEST_CRT_LAK, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        goto gen_resp;
    }
    print_hex_string("LAK crt", tmp_crt, tmp_crt_len);

    if(memcmp(buf+len, POST_ATTESTATION_REQUEST_END, sizeof(POST_ATTESTATION_REQUEST_END)) != 0){
        ret = -1;
        goto gen_resp;
    }

    // Start fields validation
    mbedtls_printf("\nValidating fields...\n");
    /*
    mbedtls_printf("Verifying nonce - ");
    if(memcmp(ref_nonce, nonce, NONCE_LEN) != 0) {
        mbedtls_printf("error\n");
        mbedtls_x509_crt_free(&dice_certs);
        ret = 9;
        goto gen_resp;
    }
    mbedtls_printf("ok\n");
    */

    ret = mbedtls_x509_crt_parse_der(&trusted_certs, ref_cert_man, ref_cert_man_len);
    mbedtls_printf("Parsing Trusted Certificate - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_mbedtls_x509_cert("Trusted Certificate", trusted_certs);
    #endif
    if(ret != 0) {
        goto gen_resp;
    }

    // cert_chain.hash.p[15] = 0x56; // Used to break verification

    //  Verify chain of certificates
    ret = mbedtls_x509_crt_verify_with_profile(&dice_certs, &trusted_certs, NULL, &mbedtls_x509_crt_profile_keystone, NULL, &flags, NULL, NULL);
    mbedtls_printf("Verifing Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
    if(ret != 0) {
        goto gen_resp;
    }

    // Verify attestation evidence signature
    // Get LAK public key
    ret = getAttestationPublicKey(&dice_certs, verification_pk);
    mbedtls_printf("Getting LAK PK - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("SM PK", verification_pk, PUBLIC_KEY_SIZE);
    #endif
    if(ret != 0) {
        goto gen_resp;
    }

    // Get enclave reference TCI
    ret = getReferenceTCI(NULL, reference_tci);
    mbedtls_printf("Getting Enclave Reference TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        goto gen_resp;
    }

    // Compute reference attestation evidence
    sha3_init(&ctx_hash, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, nonce, NONCE_LEN);
    sha3_update(&ctx_hash, reference_tci, KEYSTONE_HASH_MAX_SIZE);
    sha3_update(&ctx_hash, pk, PUBLIC_KEY_SIZE);
    sha3_final(fin_hash, &ctx_hash);
    #if PRINT_STRUCTS
    print_hex_string("fin_hash", fin_hash, KEYSTONE_HASH_MAX_SIZE);
    #endif

    // Verify signature of the attestation evidence
    ret = mbedtls_pk_parse_ed25519_key(&key, verification_pk, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing LAK PK - ret: %d\n", ret);
    if(ret != 0) {
        goto gen_resp;
    }

    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_ED25519, NULL, &key, MBEDTLS_MD_KEYSTONE_SHA3, fin_hash, KEYSTONE_HASH_MAX_SIZE, attest_evd, attest_evd_len);
    mbedtls_printf("Verifying attestation evidence signature - ret: %d\n\n", ret);
    if(ret != 0) {
        goto gen_resp;
    }

gen_resp:
    mbedtls_x509_crt_free(&trusted_certs);
    mbedtls_x509_crt_free(&dice_certs);
    mbedtls_pk_free(&key);
    if(ret == 0) {
        memcpy(resp, HTTP_RESPONSE_200, sizeof(HTTP_RESPONSE_200));
        *resp_len = sizeof(HTTP_RESPONSE_200);
    }
    return ret;
}

int get_encoded_field(unsigned char *buf, size_t *index, char *format, unsigned char *output, size_t *outlen, int encoded) {
    unsigned char enc_buf[BUF_SIZE];
    size_t enc_len = 0;
    size_t outbuf_len = *outlen;
    int ret = 0;
    if(memcmp(buf+(*index), format, strlen(format))!=0) {
        mbedtls_printf("Error 1\n");
        return -1;
    }
    *index += strlen(format);
    while(buf[(*index)+enc_len] != '"' && buf[(*index)+enc_len] != '\0')
        enc_len ++;
    if(buf[(*index)+enc_len] == '\0') {
        mbedtls_printf("Error 2\n");
        return -1;
    }
    memcpy(enc_buf, buf+(*index), enc_len);
    // mbedtls_printf("output: %s, %lu\n", enc_buf, enc_len);
    // mbedtls_printf("output_len: %lu\n", strlen((char*) enc_buf));
    // mbedtls_printf("format_len: %lu\n", strlen(format));
    *index += enc_len;
    if(encoded) {
        if((ret = mbedtls_base64_decode(output, outbuf_len, outlen, enc_buf, enc_len)) != 0) {
            mbedtls_printf("Error 3\n");
            return ret;
        }
    } else {
        memcpy(output, enc_buf, enc_len);
        *outlen = enc_len;
    }
    return 0;
}