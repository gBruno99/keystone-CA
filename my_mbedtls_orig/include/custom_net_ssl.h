#ifndef CUSTOM_MBEDTLS_NET_SSL_H
#define CUSTOM_MBEDTLS_NET_SSL_H

/**
 * Wrapper type for sockets.
 *
 * Currently backed by just a file descriptor, but might be more in the future
 * (eg two file descriptors for combined IPv4 + IPv6 support, or additional
 * structures for hand-made UDP demultiplexing).
 */
typedef struct mbedtls_net_context {
    /** The underlying file descriptor.
     *
     * This field is only guaranteed to be present on POSIX/Unix-like platforms.
     * On other platforms, it may have a different type, have a different
     * meaning, or be absent altogether.
     */
    int fd;
}
mbedtls_net_context;

// net_sockets.h
void mbedtls_net_init(mbedtls_net_context *ctx);
int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);
int mbedtls_net_bind(mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto);
int mbedtls_net_accept(mbedtls_net_context *bind_ctx, mbedtls_net_context *client_ctx, void *client_ip, size_t buf_size, size_t *ip_len);
void mbedtls_net_free(mbedtls_net_context *ctx);

#endif