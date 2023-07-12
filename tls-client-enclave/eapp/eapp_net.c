#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include "mbedtls/platform.h"

#define OCALL_NET_CONNECT 1

typedef struct {
  int fd;
  int retval;
} net_connect_t;


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