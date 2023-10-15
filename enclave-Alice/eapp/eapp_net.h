#ifndef _EAPP_NET_H_
#define _EAPP_NET_H_

#include "mbedtls/net_sockets.h"

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

void custom_net_init(mbedtls_net_context *ctx);
int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);
int custom_net_send(void *ctx, const unsigned char *buf, size_t len);
int custom_net_recv(void *ctx, unsigned char *buf, size_t len);
void custom_net_free(mbedtls_net_context *ctx);


#endif