#ifndef _EAPP_NET_H_
#define _EAPP_NET_H_

#include "mbedtls/net_sockets.h"

#define SERVER_PORT "8067"
#define SERVER_NAME "192.168.100.2"

#define GET_NONCE_REQUEST \
    "GET /nonce HTTP/1.0\r\nContent-Length: 0\r\n\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " 

#define HTTP_NONCE_RESPONSE_MIDDLE \
    "\r\n\r\n{\r\n    \"nonce\": \""

#define HTTP_NONCE_RESPONSE_END \
    "\"\r\n}\r\n"

#define POST_CSR_REQUEST_START \
    "POST /csr HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n" 

#define POST_CSR_REQUEST_END \
    "{\r\n    \"csr\": \"%s\"\r\n}\r\n" 

#define HTTP_CERTIFICATE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " 

#define HTTP_CERTIFICATE_RESPONSE_MIDDLE \
    "\r\n\r\n{\r\n    \"crt\": \"" 

#define HTTP_CERTIFICATE_RESPONSE_END \
    "\"\r\n}\r\n"

#define HTTP_RESPONSE_400 \
    "HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_500 \
    "HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"

void custom_net_init(mbedtls_net_context *ctx);
int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);
int custom_net_send(void *ctx, const unsigned char *buf, size_t len);
int custom_net_recv(void *ctx, unsigned char *buf, size_t len);
void custom_net_free(mbedtls_net_context *ctx);


#endif