#ifndef _FIREWALL_KERNEL_COMM_H
#define _FIREWALL_KERNEL_COMM_H

#include "share.h"
#include "comm_protocol.h"
#include "common.h"
#include "core.h"

// Netlink API

// int send(unsigned int pid, void *data, unsigned int len);
int send(unsigned int pid, void *header, void *body, unsigned int header_len, unsigned int body_len);
void receive(struct sk_buff *skb);
struct sock *netlink_init();
void netlink_release();

int process_user_request(unsigned int pid, void *data, unsigned int len);

void process_manage(Manage *manage);

#endif /*_FIREWALL_KERNEL_COMM_H*/