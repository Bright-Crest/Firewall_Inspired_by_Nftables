/**
 * @file kernel_comm.h
 * @author Bright-Crest (stephenzhu2004@163.com)
 * @brief Kernel-space communication API based on Netlink.
 * @date 2024/07
 */

#ifndef _FIREWALL_KERNEL_COMM_H
#define _FIREWALL_KERNEL_COMM_H

#include "share.h"
#include "comm_protocol.h"
#include "common.h"
#include "core.h"
#include "rules.h"

// Netlink API

int send(unsigned int pid, void *data, unsigned int len);
// int send(unsigned int pid, void *header, void *body, unsigned int header_len, unsigned int body_len);
void receive(struct sk_buff *skb);
struct sock *netlink_init();
void netlink_release();

unsigned int process_user_request(unsigned int pid, void *data, unsigned int len);
void process_manage(unsigned int pid, Manage *manage);
void manage_usr_req(unsigned int pid, Manage *manage);

int sendmsg(unsigned int pid, const char *msg);

#endif /*_FIREWALL_KERNEL_COMM_H*/