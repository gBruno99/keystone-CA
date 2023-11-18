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
#include "mbedtls/x509_csr.h"
#include "mbedtls/keystone_ext.h"
#include "mbedtls/print.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "custom_certs.h"
#include "mbedtls/sha3.h"
#include "host/net.h"

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

#define STATUS_OK           0
#define STATUS_BAD_REQUEST  1
#define STATUS_SERVER_ERROR 2
#define STATUS_FORBIDDEN    3

#define PRINT_STRUCTS 0

#define DEBUG_LEVEL 0

int verify_attest_evidence(unsigned char *buf, size_t buf_len, unsigned char *resp, size_t *resp_len);

int get_encoded_field(unsigned char *buf, size_t buf_len, size_t *index, char *format, unsigned char *output, size_t *outlen, int encoded);

int send_buf(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t *len);

int recv_buf(mbedtls_ssl_context *ssl, unsigned char *buf, size_t *len, unsigned char *data, size_t *data_len, 
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len));

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
    int ret;
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

    unsigned char resp[RESPONSE_MAX_LEN];
    size_t resp_len;

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

    // Step 1: Receive attestation message and verify it
    // Wait for attestation message
    if((ret = recv_buf(&ssl, buf, &len, resp, &resp_len, verify_attest_evidence))!=NET_SUCCESS){
        if(ret == HANDLER_ERROR) {
            ret = len;
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
    int (*handler)(unsigned char *recv_buf, size_t recv_buf_len, unsigned char *out_data, size_t *out_len)) {
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

int verify_attest_evidence(unsigned char *buf, size_t buf_len, unsigned char *resp, size_t *resp_len) {
    int ret = 0;
    size_t len = 0;
    unsigned char o[CN_MAX_LEN] = {0};
    size_t o_len = CN_MAX_LEN;
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
    int msg = STATUS_OK;

    mbedtls_x509_crt_init(&dice_certs);
    mbedtls_x509_crt_init(&trusted_certs);
    mbedtls_pk_init(&key);

    mbedtls_printf("\n2.21 Reading attestation message...\n");

    if (sscanf((const char *)buf, POST_ATTESTATION_REQUEST_START, &body_len) != 1) {
        ret = -1;
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }

    // mbedtls_printf("body_len: %lu\n", body_len);

    tmp_len = body_len;
    while(tmp_len > 0) { 
        digits++;
        tmp_len/=10;
    } 
    digits -= 3;
    len = sizeof(POST_ATTESTATION_REQUEST_START)-1+digits;

    if(body_len == 0 || body_len > buf_len-len) {
        mbedtls_printf("Received less bytes than expected 1\n\n");
        // mbedtls_printf("body_len: %lu, buf_len: %lu, digits: %d\n", body_len, buf_len, digits);
        ret = -1;
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }

    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_SUBJECT, o, &o_len, 0)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    mbedtls_printf("O: %s, %lu\n", o, o_len);
       
    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_PK, pk, &pk_len, 1)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("PK", pk, pk_len);
    
    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_NONCE, nonce, &nonce_len, 1)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("nonce", nonce, nonce_len);

    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_ATTEST_SIG, attest_evd, &attest_evd_len, 1)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("attest_evd_sign", attest_evd, attest_evd_len);

    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_CRT_DEVROOT, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("DevRoot crt", tmp_crt, tmp_crt_len);
    tmp_crt_len = CERTS_MAX_LEN;

    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_CRT_SM, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("SM ECA crt", tmp_crt, tmp_crt_len);
    tmp_crt_len = CERTS_MAX_LEN;

    if((ret = get_encoded_field(buf, buf_len, &len, POST_ATTESTATION_REQUEST_CRT_LAK, tmp_crt, &tmp_crt_len, 1)) != 0 ||
        (ret = mbedtls_x509_crt_parse_der(&dice_certs, tmp_crt, tmp_crt_len)) != 0) {
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }
    print_hex_string("LAK crt", tmp_crt, tmp_crt_len);

    if(memcmp(buf+len, POST_ATTESTATION_REQUEST_END, sizeof(POST_ATTESTATION_REQUEST_END)) != 0){
        ret = -1;
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }

    len += sizeof(POST_ATTESTATION_REQUEST_END);
    if(body_len != (len-(sizeof(POST_ATTESTATION_REQUEST_START)-1+digits)-1)) {
        mbedtls_printf("Received less bytes than expected 2\n\n");
        // mbedtls_printf("body_len: %lu, len: %lu, digits: %d\n", body_len, len, digits);
        ret = -1;
        msg = STATUS_BAD_REQUEST;
        goto gen_resp;
    }

    // Start fields validation
    mbedtls_printf("\nValidating fields...\n");

    ret = mbedtls_x509_crt_parse_der(&trusted_certs, ref_cert_man, ref_cert_man_len);
    mbedtls_printf("Parsing Trusted Certificate - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_mbedtls_x509_cert("Trusted Certificate", trusted_certs);
    #endif
    if(ret != 0) {
        msg = STATUS_SERVER_ERROR;
        goto gen_resp;
    }

    // cert_chain.hash.p[15] = 0x56; // Used to break verification

    //  Verify chain of certificates
    ret = mbedtls_x509_crt_verify_with_profile(&dice_certs, &trusted_certs, NULL, &mbedtls_x509_crt_profile_keystone, NULL, &flags, NULL, NULL);
    mbedtls_printf("Verifing Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
    if(ret != 0) {
        msg = STATUS_FORBIDDEN;
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
        msg = STATUS_SERVER_ERROR;
        goto gen_resp;
    }

    // Get enclave reference TCI
    ret = getReferenceTCI((char*) o, reference_tci);
    mbedtls_printf("Getting Enclave Reference TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, KEYSTONE_HASH_MAX_SIZE);
    #endif
    if(ret != 0) {
        msg = STATUS_SERVER_ERROR;
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
        msg = STATUS_SERVER_ERROR;
        goto gen_resp;
    }

    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_ED25519, NULL, &key, MBEDTLS_MD_KEYSTONE_SHA3, fin_hash, KEYSTONE_HASH_MAX_SIZE, attest_evd, attest_evd_len);
    mbedtls_printf("Verifying attestation evidence signature - ret: %d\n\n", ret);
    if(ret != 0) {
        msg = STATUS_FORBIDDEN;
        goto gen_resp;
    }

gen_resp:
    mbedtls_x509_crt_free(&trusted_certs);
    mbedtls_x509_crt_free(&dice_certs);
    mbedtls_pk_free(&key);
    switch(msg) {
        case STATUS_OK:
            memcpy(resp, HTTP_RESPONSE_200, sizeof(HTTP_RESPONSE_200));
            *resp_len = sizeof(HTTP_RESPONSE_200);
            break;
        case STATUS_BAD_REQUEST:
            memcpy(resp, HTTP_RESPONSE_400, sizeof(HTTP_RESPONSE_400));
            *resp_len = sizeof(HTTP_RESPONSE_400);
            break;
        case STATUS_FORBIDDEN:
            memcpy(resp, HTTP_RESPONSE_403, sizeof(HTTP_RESPONSE_403));
            *resp_len = sizeof(HTTP_RESPONSE_403);
            break;
        default:
            memcpy(resp, HTTP_RESPONSE_500, sizeof(HTTP_RESPONSE_500));
            *resp_len = sizeof(HTTP_RESPONSE_500);
            break;
    }
    return ret;
}

int get_encoded_field(unsigned char *buf, size_t buf_len, size_t *index, char *format, unsigned char *output, size_t *outlen, int encoded) {
    unsigned char enc_buf[BUF_SIZE];
    size_t enc_len = 0;
    size_t outbuf_len = *outlen;
    int ret = 0;
    if(memcmp(buf+(*index), format, strlen(format))!=0) {
        mbedtls_printf("Error 1\n");
        return -1;
    }
    *index += strlen(format);
    while(((*index) + enc_len) < buf_len && buf[(*index)+enc_len] != '"' && buf[(*index)+enc_len] != '\0')
        enc_len ++;
    if(((*index) + enc_len) >= buf_len || buf[(*index)+enc_len] == '\0' || enc_len == 0) {
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
