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

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "custom_functions.h"
#include "ed25519/ed25519.h"
#include "sha3/sha3.h"

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define GET_NONCE_REQUEST "GET /nonce HTTP/1.0\r\n\r\n"

#define POST_CSR_SIZE_REQUEST \
    "POST /csr/size HTTP/1.0\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Client Alice - csr len</h2>\r\n" \
    "<p>%d</p>\r\n"

#define POST_CSR_REQUEST_START \
    "POST /csr HTTP/1.0\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Client Alice - csr</h2>\r\n" \
    "<p>"

#define POST_CSR_REQUEST_END \
    "</p>\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>CA Server - nonce</h2>\r\n" \
    "<p>"

#define HTTP_NONCE_RESPONSE_END \
"</p>\r\n"

#define HTTP_CERTIFICATE_SIZE_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>CA Server - crt len</h2>\r\n" \
    "<p>%d</p>\r\n"

#define HTTP_CERTIFICATE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>CA Server - crt</h2>\r\n" \
    "<p>"

#define HTTP_CERTIFICATE_RESPONSE_END \
"</p>\r\n"

#define DEBUG_LEVEL 0
#define PRINT_STRUCTS 0

#define HASH_LEN 64
#define PARSE_PUBLIC_KEY    0
#define PARSE_PRIVATE_KEY   1

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

int print_hex_string(char* name, unsigned char* value, int size){
  mbedtls_printf("%s: 0x", name);
  for(int i = 0; i< size; i++){
    mbedtls_printf("%02x", value[i]);
  }
  mbedtls_printf("\n");
  mbedtls_printf("%s_len: %d\n", name, size);
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
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[2048];
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
    mbedtls_printf("[S]  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
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

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf("[S]  < Read from client:");
    fflush(stdout);

    // Wait for nonce request
    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

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

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0) {
            break;
        }
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf("[S]  > Write to client:");
    fflush(stdout);

    // Write the nonce into the response
    memcpy(buf, HTTP_NONCE_RESPONSE_START, sizeof(HTTP_NONCE_RESPONSE_START)-1);
    len = sizeof(HTTP_NONCE_RESPONSE_START)-1;
    memcpy(buf+len, nonce, sizeof(nonce));
    len += sizeof(nonce);
    memcpy(buf+len, HTTP_NONCE_RESPONSE_END, sizeof(HTTP_NONCE_RESPONSE_END));
    len += sizeof(HTTP_NONCE_RESPONSE_END);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[S]  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

    unsigned char recv_csr[2048] = {0};
    int csr_len = 0;

    // Wait for CSR len
    mbedtls_printf("[S]  < Read from client:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

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

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0) {
            // Read csr len from the request
            if(sscanf((const char *)buf, POST_CSR_SIZE_REQUEST, &csr_len)!=1) {
                mbedtls_printf("Error in reading csr_len\n");
                goto exit;
            }
            mbedtls_printf("[S] csr_len=%d\n", csr_len);
            break;
        }
    } while (1);

    mbedtls_printf("[S]  < Read from client:");
    fflush(stdout);

    // Wait for CSR
    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

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

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0) {
            // Read CSR from the request
            if(memcmp(buf, POST_CSR_REQUEST_START, sizeof(POST_CSR_REQUEST_START)-1)!=0) {
                mbedtls_printf("[S] cannot read csr 1\n\n");
                break;
            }
            memcpy(recv_csr, buf+sizeof(POST_CSR_REQUEST_START)-1, csr_len);
            if(memcmp(buf+sizeof(POST_CSR_REQUEST_START)-1+csr_len, POST_CSR_REQUEST_END, sizeof(POST_CSR_REQUEST_END))!=0){
                mbedtls_printf("[S] cannot read csr 2\n\n");
                goto exit;
            }
            print_hex_string("[S] csr", recv_csr, csr_len);
            break;
        }
    } while (1);

    // Parse and verify CSR
    mbedtls_printf("[S] Parsing CSR...\n\n");
    custom_x509_csr csr;
    custom_x509_csr_init(&csr);

    ret = custom_x509_csr_parse_der(&csr, recv_csr, csr_len);
    mbedtls_printf("Parsing CSR - ret: %d\n", ret);
    mbedtls_printf("\n");

    // verify CSR signature
    mbedtls_printf("[S] Verifying CSR...\n\n");
    unsigned char csr_hash[64] = {0};
    ret = custom_md(custom_md_info_from_type(csr.sig_md), csr.cri.p, csr.cri.len, csr_hash);
    mbedtls_printf("Hashing CSR- ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Hash CSR", csr_hash, HASH_LEN);
    #endif
    ret = custom_pk_verify_ext(csr.sig_pk, csr.sig_opts, &(csr.pk), csr.sig_md, csr_hash, HASH_LEN, csr.sig.p, csr.sig.len);
    mbedtls_printf("Verify CSR signature - ret: %d\n", ret);
    mbedtls_printf("\n");

    // verify nonces equality
    ret = csr.nonce.len != NONCE_LEN;
    mbedtls_printf("Verify nonce len - ret: %d\n", ret);
    ret = custom_memcmp(csr.nonce.p, nonce, NONCE_LEN);
    mbedtls_printf("Verify nonce value - ret: %d\n", ret);
    mbedtls_printf("\n");

    // parse trusted certificate
    uint32_t flags = 0;
    custom_x509_crt trusted_certs;

    custom_x509_crt_init(&trusted_certs);
    ret = custom_x509_crt_parse_der(&trusted_certs, ref_cert_man, ref_cert_man_len);
    mbedtls_printf("Parsing Trusted Certificate - ret: %d\n", ret);

    #if PRINT_STRUCTS
    print_custom_x509_cert("Trusted Certificate", trusted_certs);
    #endif

    // cert_chain.hash.p[15] = 0x56; // Used to break verification

    //  verify chain of certificates
    ret = custom_x509_crt_verify(&(csr.cert_chain), &trusted_certs, NULL, NULL, &flags, NULL, NULL);
    mbedtls_printf("Verifing Chain of Certificates - ret: %u, flags = %u\n", ret, flags);
    mbedtls_printf("\n");

    custom_x509_crt_free(&trusted_certs);

    // verify attestation proof
    unsigned char verification_pk[PUBLIC_KEY_SIZE] = {0};
    unsigned char reference_tci[HASH_LEN] = {0};
    unsigned char fin_hash[HASH_LEN] = {0};
    sha3_ctx_t ctx_hash;
    ret = getAttestationPublicKey(&csr, verification_pk);
    mbedtls_printf("Getting SM PK - ret: %d\n", ret);

    #if PRINT_STRUCTS
    print_hex_string("SM PK", verification_pk, PUBLIC_KEY_SIZE);
    #endif

    ret = getReferenceTCI(&csr, reference_tci);
    mbedtls_printf("Getting Reference Enclave TCI - ret: %d\n", ret);
    #if PRINT_STRUCTS
    print_hex_string("Reference Enclave TCI", reference_tci, HASH_LEN);
    #endif

    sha3_init(&ctx_hash, HASH_LEN);
    sha3_update(&ctx_hash, nonce, NONCE_LEN);
    sha3_update(&ctx_hash, reference_tci, HASH_LEN);
    sha3_update(&ctx_hash, custom_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE);
    sha3_final(fin_hash, &ctx_hash);

    #if PRINT_STRUCTS
    print_hex_string("fin_hash", fin_hash, HASH_LEN);
    #endif

    custom_pk_context key;
    custom_pk_init(&key);
    ret = custom_pk_parse_public_key(&key, verification_pk, PUBLIC_KEY_SIZE, 0);
    mbedtls_printf("Parsing SM PK - ret: %d\n", ret);

    ret = custom_pk_verify_ext(CUSTOM_PK_ED25519, NULL, &key, CUSTOM_MD_KEYSTONE_SHA3, fin_hash, HASH_LEN, csr.attestation_proof.p, csr.attestation_proof.len);
    mbedtls_printf("Verifying attestation proof - ret: %d\n", ret);
    mbedtls_printf("\n");
    fflush(stdout);

    custom_pk_free(&key);

    // Generate Enclave Certificate
    mbedtls_printf("[S] Generating Certificate...\n\n");

    custom_x509write_cert cert_encl;
    custom_x509write_crt_init(&cert_encl);

    ret = custom_x509write_crt_set_issuer_name(&cert_encl, "O=Certificate Authority");
    mbedtls_printf("Setting issuer - ret: %d\n", ret);
    
    ret = custom_x509write_crt_set_subject_name(&cert_encl, "CN=Client1,O=Certificate Authority");
    mbedtls_printf("Setting subject - ret: %d\n", ret);

    custom_pk_context subj_key;
    custom_pk_init(&subj_key);

    custom_pk_context issu_key;
    custom_pk_init(&issu_key);
    
    ret = custom_pk_parse_public_key(&issu_key, sanctum_ca_private_key, PRIVATE_KEY_SIZE, PARSE_PRIVATE_KEY);
    mbedtls_printf("Parsing issuer pk - ret: %d\n", ret);

    ret = custom_pk_parse_public_key(&issu_key, sanctum_ca_public_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing issuer sk - ret: %d\n", ret);

    ret = custom_pk_parse_public_key(&subj_key, custom_pk_ed25519(csr.pk)->pub_key, PUBLIC_KEY_SIZE, PARSE_PUBLIC_KEY);
    mbedtls_printf("Parsing subject pk - ret: %d\n", ret);

    custom_x509write_crt_set_subject_key(&cert_encl, &subj_key);
    mbedtls_printf("Setting subject key\n");

    custom_x509write_crt_set_issuer_key(&cert_encl, &issu_key);
    mbedtls_printf("Setting issuer keys\n");
    
    unsigned char serial[] = {0xAB, 0xAB, 0xAB};

    ret = custom_x509write_crt_set_serial_raw(&cert_encl, serial, 3);
    mbedtls_printf("Setting serial - ret: %d\n", ret);
    
    custom_x509write_crt_set_md_alg(&cert_encl, CUSTOM_MD_KEYSTONE_SHA3);
    mbedtls_printf("Setting md algorithm\n");
    
    ret = custom_x509write_crt_set_validity(&cert_encl, "20230101000000", "20240101000000");
    mbedtls_printf("Setting validity - ret: %d\n", ret);

    char oid_ext[] = {0xff, 0x20, 0xff};

    ret = custom_x509write_crt_set_extension(&cert_encl, oid_ext, 3, 0, reference_tci, HASH_LEN);
    mbedtls_printf("Setting tci - ret: %d\n", ret);

    mbedtls_printf("\n");

    // Writing certificate
    unsigned char cert_der[1024];
    int effe_len_cert_der;
    size_t len_cert_der_tot = 1024;

    ret = custom_x509write_crt_der(&cert_encl, cert_der, len_cert_der_tot, NULL, NULL);
    mbedtls_printf("Writing Enclave Certificate - ret: %d\n", ret);
    effe_len_cert_der = ret;
    
    unsigned char *cert_real = cert_der;
    int dif  = 1024-effe_len_cert_der;
    cert_real += dif;

    print_hex_string("Enclave Certificate", cert_real, effe_len_cert_der);
    fflush(stdout);

    custom_pk_free(&issu_key);
    custom_pk_free(&subj_key);
    custom_x509write_crt_free(&cert_encl);
    custom_x509_csr_free(&csr);

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf("[S]  > Write to client:");
    fflush(stdout);

     // Write certificate len
    len = sprintf((char *) buf, HTTP_CERTIFICATE_SIZE_RESPONSE, effe_len_cert_der);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[S]  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

    mbedtls_printf("[S]  > Write to client:");
    fflush(stdout);

    // Write ceritificate into response
    memcpy(buf, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1);
    len = sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1;
    memcpy(buf+len, cert_real, effe_len_cert_der);
    len += effe_len_cert_der;
    memcpy(buf+len, HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END));
    len += sizeof(HTTP_CERTIFICATE_RESPONSE_END);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n[S]  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n[S]  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

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
