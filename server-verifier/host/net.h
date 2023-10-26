#ifndef _HOST_NET_H_
#define _HOST_NET_H_

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

#define POST_ATTESTATION_REQUEST_START_SUBJECT \
    "POST /attest HTTP/1.0\r\nContent-Type: application/json\r\n\r\n" \
    "{\n\t\"subject_cn\": \""
#define POST_ATTESTATION_REQUEST_PK \
    "\",\n\t\"pk\": \""
#define POST_ATTESTATION_REQUEST_NONCE \
    "\",\n\t\"nonce\": \""
#define POST_ATTESTATION_REQUEST_ATTEST_SIG \
    "\",\n\t\"attest_evd_sig\": \""
#define POST_ATTESTATION_REQUEST_CRT_MAN\
    "\",\n\t\"dice_cert_man\": \""
#define POST_ATTESTATION_REQUEST_CRT_DEVROOT \
    "\",\n\t\"dice_cert_devroot\": \""
#define POST_ATTESTATION_REQUEST_CRT_SM \
    "\",\n\t\"dice_cert_sm\": \""
#define POST_ATTESTATION_REQUEST_END \
    "\"\n}\r\n"

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