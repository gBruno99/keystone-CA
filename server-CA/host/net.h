#ifndef _HOST_NET_H_
#define _HOST_NET_H_

#define VERIFIER_NAME "localhost"
#define VERIFIER_PORT "8068"

#define GET_NONCE_REQUEST "GET /nonce HTTP/1.0\r\n\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"nonce_len\": %lu, \"nonce\": \"" 

#define HTTP_NONCE_RESPONSE_END \
    "\"}\r\n"

#define POST_CSR_REQUEST_START \
    "POST /csr HTTP/1.0\r\nContent-Type: application/json\r\n\r\n" \
    "{\"csr_len\": %lu, \"csr\": \"" 

#define POST_CSR_REQUEST_END \
    "\"}\r\n"

#define HTTP_CERTIFICATE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"crt_len\": %lu, \"crt\": \"" 

#define HTTP_CERTIFICATE_RESPONSE_END \
    "\"}\r\n"

#define POST_ATTESTATION_REQUEST \
    "POST /attest HTTP/1.0\r\nContent-Type: application/json\r\n\r\n" \
    "{\n\t\"subject_cn\": \"%s\"," \
    "\n\t\"pk\": \"%s\"," \
    "\n\t\"nonce\": \"%s\"," \
    "\n\t\"attest_evd_sig\": \"%s\"," \
    "\n\t\"dice_cert_man\": \"%s\"," \
    "\n\t\"dice_cert_devroot\": \"%s\"," \
    "\n\t\"dice_cert_sm\": \"%s\"" \
    "\n}\r\n"

#define HTTP_RESPONSE_400 \
    "HTTP/1.0 400 BAD REQUEST\r\nContent-Type: application/json\r\n\r\n" \
    "{}\r\n" 
#define HTTP_RESPONSE_500 \
    "HTTP/1.0 500 INTERNAL SERVER ERROR\r\nContent-Type: application/json\r\n\r\n" \
    "{}\r\n" 
#define HTTP_RESPONSE_200 \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{}\r\n" 
    
#endif