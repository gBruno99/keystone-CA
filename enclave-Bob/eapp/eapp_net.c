#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include <string.h>
#include "riscv_time.h"
#include "eapp/printf.h"
// #include <stdio.h>

#define OCALL_NET_CONNECT 1
#define OCALL_NET_SEND    2
#define OCALL_NET_RECV    3
#define OCALL_NET_FREE    4
#define OCALL_NET_BIND    5
#define OCALL_NET_ACCEPT  6

typedef struct {
  int fd;
  int retval;
} net_connect_t;

#if PERFORMANCE_TEST
ticks_t t_start, t_end, t_diff;
#endif

void custom_net_init(mbedtls_net_context *ctx) {
    ctx->fd = -1;
}

int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto) {
    int ret;
    net_connect_t retval;
    char tmp[16] = {0};
    memcpy(tmp, port, 5);
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    ret = ocall(OCALL_NET_CONNECT, tmp, 5,(void*) &retval, sizeof(net_connect_t));
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    t_diff = t_end - t_start;
    custom_printf("\n[OCALL_NET_CONNECT] Ticks: %lu\n", t_diff);
    #endif
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
    unsigned  char tmp_buf[2048+sizeof(int)];
    if(len > 2048)
        return -1;
    int *fd = (int*) tmp_buf;
    *fd = ((mbedtls_net_context *) ctx)->fd;
    memcpy(tmp_buf+sizeof(int), buf, len);
    #if PERFORMANCE_TEST
    custom_printf("\n[OCALL_NET_SEND] Sending...\n");
    t_start = get_time_inline();
    #endif
    ret = ocall(OCALL_NET_SEND, (unsigned char *)tmp_buf, len+sizeof(int), &retval, sizeof(int));
    return ret|retval;
}

int custom_net_recv(void *ctx, unsigned char *buf, size_t len) {
    int ret;
    unsigned char tmp_buf[16896+sizeof(int)];
    int *fd = (int*) tmp_buf;
    *fd = ((mbedtls_net_context *) ctx)->fd;
    ret = ocall(OCALL_NET_RECV, tmp_buf, len, tmp_buf, len + sizeof(int));
    #if PERFORMANCE_TEST
    custom_printf("\n[OCALL_NET_RECV] ...Receiving\n");
    t_end = get_time_inline();
    t_diff = t_end - t_start;
    custom_printf("\nTicks between request and response: %lu\n", t_diff);
    #endif
    // printf("ocall returned %d\n", ret);
    int retval = * ((int*)tmp_buf);
    memcpy(buf, tmp_buf+sizeof(int), len);
    // printf("Asked for %lu bytes, received %d: %s\n", len, retval, tmp_buf+sizeof(int));
    // fflush(stdout);
    return ret|retval;
}

void custom_net_free(mbedtls_net_context *ctx) {
    int fd = ((mbedtls_net_context *) ctx)->fd;
    ocall(OCALL_NET_FREE, (unsigned char *) &fd, sizeof(int), NULL, 0);
}

int custom_net_bind(mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto) {
    int ret;
    net_connect_t retval;
    char tmp[16] = {0};
    memcpy(tmp, port, 5);
    ret = ocall(OCALL_NET_BIND, tmp, 5,(void*) &retval, sizeof(net_connect_t));
    ret |= retval.retval;
    // mbedtls_printf("net_connect - fd: %d, ret: %d\n", retval.fd, retval.retval);
    if(ret) {
        return ret;
    } else {
        ctx->fd = retval.fd;
    }
    return 0;
}

int custom_net_accept(mbedtls_net_context *bind_ctx, mbedtls_net_context *client_ctx, void *client_ip, size_t buf_size, size_t *ip_len) {
    int fd = ((mbedtls_net_context *) bind_ctx)->fd;
    int ret;
    net_connect_t retval;
    #if PERFORMANCE_TEST
    t_start = get_time_inline();
    #endif
    ret = ocall(OCALL_NET_ACCEPT, (unsigned char *) &fd, sizeof(int), (void*) &retval, sizeof(net_connect_t));
    #if PERFORMANCE_TEST
    t_end = get_time_inline();
    t_diff = t_end - t_start;
    custom_printf("\n[OCALL_NET_ACCEPT] Ticks: %lu\n", t_diff);
    #endif
    ret |= retval.retval;
    // mbedtls_printf("net_connect - fd: %d, ret: %d\n", retval.fd, retval.retval);
    if(ret) {
        return ret;
    } else {
        client_ctx->fd = retval.fd;
    }
    return 0;
}