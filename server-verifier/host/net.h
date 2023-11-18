#ifndef _HOST_NET_H_
#define _HOST_NET_H_

#define POST_ATTESTATION_REQUEST_START \
    "POST /attest HTTP/1.1\r\nHost: www.ver.org\r\nContent-Type: application/json\r\nContent-Length: %lu\r\n\r\n"

#define POST_ATTESTATION_REQUEST_SUBJECT \
    "{\r\n    \"subject_o\": \""
    
#define POST_ATTESTATION_REQUEST_PK \
    "\",\r\n    \"pk\": \""

#define POST_ATTESTATION_REQUEST_NONCE \
    "\",\r\n    \"nonce\": \""

#define POST_ATTESTATION_REQUEST_ATTEST_SIG \
    "\",\r\n    \"attest_evd_sig\": \""

#define POST_ATTESTATION_REQUEST_CRT_DEVROOT \
    "\",\r\n    \"dice_cert_devroot\": \""

#define POST_ATTESTATION_REQUEST_CRT_SM \
    "\",\r\n    \"dice_cert_sm\": \""

#define POST_ATTESTATION_REQUEST_CRT_LAK\
    "\",\r\n    \"dice_cert_lak\": \""

#define POST_ATTESTATION_REQUEST_END \
    "\"\r\n}\r\n"

#define HTTP_RESPONSE_400 \
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_403 \
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_500 \
    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"

#define HTTP_RESPONSE_200 \
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    
#endif