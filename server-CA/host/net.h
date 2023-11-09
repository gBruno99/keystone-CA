#ifndef _HOST_NET_H_
#define _HOST_NET_H_

#define VERIFIER_NAME "Ver"
#define VERIFIER_PORT "8068"

#define GET_NONCE_REQUEST \
    "GET /nonce HTTP/1.1\r\nHost: www.ca.org\r\nContent-Length: 0\r\n\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n" 

#define HTTP_NONCE_RESPONSE_END \
    "{\r\n    \"nonce\": \"%s\"\r\n}\r\n" 

#define POST_CSR_REQUEST_START \
    "POST /csr HTTP/1.1\r\nHost: www.ca.org\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n" 

#define POST_CSR_REQUEST_MIDDLE \
    "{\r\n    \"csr\": \"" 

#define POST_CSR_REQUEST_END \
    "\"\r\n}\r\n"

#define HTTP_CERTIFICATE_RESPONSE_START \
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n" \

#define HTTP_CERTIFICATE_RESPONSE_END \
    "{\r\n    \"crt\": \"%s\"\r\n}\r\n" 

#define POST_ATTESTATION_REQUEST_START \
    "POST /attest HTTP/1.1\r\nHost: www.ver.org\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n"

#define POST_ATTESTATION_REQUEST_END \
    "{\r\n    \"subject_cn\": \"%s\",\r\n" \
    "    \"pk\": \"%s\",\r\n" \
    "    \"nonce\": \"%s\",\r\n" \
    "    \"attest_evd_sig\": \"%s\",\r\n" \
    "    \"dice_cert_devroot\": \"%s\",\r\n" \
    "    \"dice_cert_sm\": \"%s\",\r\n" \
    "    \"dice_cert_lak\": \"%s\"\r\n}\r\n"

#define HTTP_RESPONSE_400 \
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_403 \
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_500 \
    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_200 \
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    
#endif