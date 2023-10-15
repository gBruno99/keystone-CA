#ifndef _HOST_NET_H_
#define _HOST_NET_H_

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

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

#define HTTP_CERTIFICATE_SIZE_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"crt_len\": %d, " 

#define HTTP_CERTIFICATE_RESPONSE_START \
    "\"crt\": \"0x" 

#define HTTP_CERTIFICATE_RESPONSE_END \
    "\"}\r\n"
    
#endif