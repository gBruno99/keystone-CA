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
#include "certs.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/keystone_ext.h"
#include "mbedtls/print.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

// #include "mbedtls_functions.h"
// #include "ed25519/ed25519.h"
#include "mbedtls/sha3.h"
#include "host/net.h"
#include "host/ref_certs.h"

#define BUF_SIZE                2048
#define CSR_MAX_LEN             3072
#define CERTS_MAX_LEN           1024

#define NET_SUCCESS     -1
#define HANDLER_ERROR   -2
#define GOTO_EXIT       -3
#define GOTO_RESET      -4

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

int check_nonce_request(unsigned char *buf, unsigned char *nonce, int *nonce_len);

int get_csr(unsigned char *buf, unsigned char *csr, int *csr_len);

int verify_csr(unsigned char *recv_csr, int csr_len, unsigned char *nonce);

int issue_crt(unsigned char *recv_csr, int csr_len, unsigned char *crt, int *crt_len);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, int *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, int *len, unsigned char *data, int *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, int *out_len));

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
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[BUF_SIZE];
    const char *pers = "ssl_server";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    unsigned char nonce[] = {
        0x95, 0xb2, 0xcd, 0xbd, 0x9c, 0x3f, 0xe9, 0x28, 0x16, 0x2f, 0x4d, 0x86, 0xc6, 0x5e, 0x2c, 0x23,
        0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96, 0x6f, 0x7c, 0x1f, 0xf3
    };
    unsigned char recv_csr[CSR_MAX_LEN] = {0};
    int csr_len = 0;
    unsigned char crt[CERTS_MAX_LEN] = {0};
    int crt_len = 0;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1. Seed the RNG
     */
    mbedtls_printf("[S]  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    mbedtls_printf("\n[S]  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                                 mbedtls_test_srv_crt_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[S]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n[S]  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                                mbedtls_test_srv_key_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" failed\n[S]  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    mbedtls_printf("[S]  . Bind on https://localhost:8067/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "8067", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("[S]  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("[S] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("[S]  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n[S]  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("[S]  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    // Step 1: Receive request and send nonce
    // Read request
    if((ret = recv_buf(&ssl, buf, &len, NULL, NULL, check_nonce_request))!=NET_SUCCESS){
        goto reset;
    }

    // Write the nonce into the response
    memcpy(buf, HTTP_NONCE_RESPONSE_START, sizeof(HTTP_NONCE_RESPONSE_START)-1);
    len = sizeof(HTTP_NONCE_RESPONSE_START)-1;
    memcpy(buf+len, nonce, sizeof(nonce));
    len += sizeof(nonce);
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
        goto exit;
    }

    print_hex_string("[S] CSR", recv_csr, csr_len);
    
    // Parse and verify CSR
    if((ret = verify_csr(recv_csr, csr_len, nonce))!=0){
        ret = -1;
        goto exit;
    }

    // Step 3: Issue LDevID Certificate for Enclave and send it
    mbedtls_printf("[S] Generating Certificate...\n\n");
    if((ret = issue_crt(recv_csr, csr_len, crt, &crt_len)) != 0) {
        ret = -1;
        goto exit;
    }

    // Generate response
    // Write certificate len
    len = sprintf((char *) buf, HTTP_CERTIFICATE_SIZE_RESPONSE, crt_len);
    // Write ceritificate into response
    memcpy(buf+len, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1);
    len += sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1;
    memcpy(buf+len, crt, crt_len);
    len += crt_len;
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

    mbedtls_printf("[S]  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
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
        mbedtls_printf("[S] Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
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

int check_nonce_request(unsigned char *buf, unsigned char *nonce, int *nonce_len) {
    if(memcmp(buf, GET_NONCE_REQUEST, sizeof(GET_NONCE_REQUEST))!=0) {
        mbedtls_printf("Error in reading nonce request\n");
        return -1;
    }
    return 0;
}

int get_csr(unsigned char *buf, unsigned char *csr, int *csr_len) {
    // Read csr_len from the request
    if (sscanf((const char *)buf, POST_CSR_REQUEST_START, csr_len) != 1) {
        mbedtls_printf("Error in reading csr_len\n");
        return -1;
    }
    mbedtls_printf("[S] csr_len=%d\n", *csr_len);
    // Read CSR from the request
    memcpy(csr, buf + sizeof(POST_CSR_REQUEST_START), *csr_len);
    
    if (memcmp(buf + sizeof(POST_CSR_REQUEST_START) + (*csr_len), POST_CSR_REQUEST_END, sizeof(POST_CSR_REQUEST_END)) != 0) {
        mbedtls_printf("[S] cannot read csr 2\n\n");
        return -1;
    }
    return 0;
}

int verify_csr(unsigned char *recv_csr, int csr_len, unsigned char *nonce) {
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
    mbedtls_printf("[S] Verifying CSR...\n");
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
    mbedtls_printf("Verify CSR signature - ret: %d\n", ret);
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
    ret = memcmp(csr.nonce.p, nonce, NONCE_LEN);
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
    ret = getAttestationPublicKey(&csr, verification_pk);
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
    sha3_update(&ctx_hash, nonce, NONCE_LEN);
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
    mbedtls_printf("Verifying attestation proof - ret: %d\n", ret);
    mbedtls_pk_free(&key);
    mbedtls_x509_csr_free(&csr);
    if(ret != 0) {
        return 11;
    }

    mbedtls_printf("\n");
    fflush(stdout);
    return 0;
}

int issue_crt(unsigned char *recv_csr, int csr_len, unsigned char *crt, int *crt_len) {
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
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        return 9;
    }

    // Set certificate fields
    mbedtls_x509write_crt_init(&cert_encl);

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
    mbedtls_printf("Parsing issuer pk - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 4;
    }

    ret = mbedtls_pk_parse_ed25519_key(&issu_key, sanctum_ca_public_key, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing issuer sk - ret: %d\n", ret);
    if(ret != 0) {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&cert_encl);
        mbedtls_pk_free(&subj_key);
        mbedtls_pk_free(&issu_key);
        return 5;
    }

    ret = mbedtls_pk_parse_ed25519_key(&subj_key, mbedtls_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE, ED25519_PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing subject pk - ret: %d\n", ret);
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
    mbedtls_printf("Setting tci - ret: %d\n", ret);
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
    fflush(stdout);

    mbedtls_pk_free(&issu_key);
    mbedtls_pk_free(&subj_key);
    mbedtls_x509write_crt_free(&cert_encl);
    mbedtls_x509_csr_free(&csr);
    return 0;
}

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, int *len) {
    int ret;
    mbedtls_printf("[S]  > Write to client:");
    fflush(stdout);

    while ((ret = mbedtls_ssl_write(ssl, buf, *len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[S]  ! peer closed the connection\n\n");
            *len = ret;
            return GOTO_RESET;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_write returned %d\n\n", ret);
            *len = ret;
            return GOTO_EXIT;
        }
    }

    *len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", *len, (char *) buf);
    return NET_SUCCESS;
}

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, int *len, unsigned char *data, int *data_len, 
    int (*handler)(unsigned char *recv_buf, unsigned char *out_data, int *out_len)) {
    int ret;
    mbedtls_printf("[S]  < Read from client:");
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
        mbedtls_printf(" %d bytes read\n\n%s", *len, (char *) buf);

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
