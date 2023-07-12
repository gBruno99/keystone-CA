#ifndef _EAPP_NET_H_
#define _EAPP_NET_H_

#include "mbedtls/net_sockets.h"

int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);


#endif