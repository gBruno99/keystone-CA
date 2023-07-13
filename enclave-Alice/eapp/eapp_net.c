#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include <string.h>

#define OCALL_NET_CONNECT 1
#define OCALL_NET_SEND    2
#define OCALL_NET_RECV    3
#define OCALL_NET_FREE    4

typedef struct {
  int fd;
  int retval;
} net_connect_t;

void custom_net_init(mbedtls_net_context *ctx) {
    ctx->fd = -1;
}

int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto) {
    int ret;
    net_connect_t retval;
    ret = ocall(OCALL_NET_CONNECT, NULL, 0,(void*) &retval, sizeof(net_connect_t));
    ret |= retval.retval;
    // mbedtls_printf("net_connect - fd: %d, ret: %d\n", retval.fd, retval.retval);
    if(ret) {
        return ret;
    } else {
        ctx->fd = retval.fd;
    }
    return 0;
}

int custom_net_send(void *ctx, const unsigned char *buf, size_t len) {
    int ret, retval;
    ret = ocall(OCALL_NET_SEND, (unsigned char *)buf, len, &retval, sizeof(int));
    return ret|retval;
}

int custom_net_recv(void *ctx, unsigned char *buf, size_t len) {
    int ret;
    unsigned char tmp_buf[2048+sizeof(int)];
    if(tmp_buf == NULL)
        return -1;
    ret = ocall(OCALL_NET_RECV, tmp_buf, len, tmp_buf, len + sizeof(int));
    int retval = * ((int*)tmp_buf);
    memcpy(buf, tmp_buf+sizeof(int), len);
    return ret|retval;
}

void custom_net_free(mbedtls_net_context *ctx) {
    ocall(OCALL_NET_FREE, NULL, 0, NULL, 0);
}