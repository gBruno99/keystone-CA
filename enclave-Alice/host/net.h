#ifndef _HOST_NET_H_
#define _HOST_NET_H_

void
net_connect_wrapper(void* buffer);
void
net_send_wrapper(void* buffer);
void
net_recv_wrapper(void* buffer);
void
net_free_wrapper(void* buffer);
void
net_bind_wrapper(void* buffer);
void 
net_accept_wrapper(void* buffer);

#endif
