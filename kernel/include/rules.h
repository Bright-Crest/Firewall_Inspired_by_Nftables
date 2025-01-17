#ifndef _FIREWALL_RULES_H
#define _FIREWALL_RULES_H

// 内核模块编写的的依赖头文件
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>

#include "share.h"

#define DEFAULT_ACTION NF_ACCEPT

struct FilterRule
{
    char name[MAX_NAME_LENGTH+ 1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int taddr;
    unsigned int tmask;
    unsigned int sport;
    unsigned int tport;
    u_int8_t protocol;
    unsigned int act;
    unsigned int islog;
    struct FilterRule *next;
};

struct FTRule_Chain
{
    char name[MAX_NAME_LENGTH+ 1];
    struct FilterRule *chain_head;
    struct FTRule_Chain *next;
    unsigned int applyloc;
};


unsigned int add_rule(char chain_name[], char after[], struct FilterRule rule);

unsigned int addRule_chain(char after[], struct FTRule_Chain chain);

unsigned int delRule(char chain_name[],char name[]);

unsigned int delRule_chain(char chain_name[]);

int ftrule_match(struct sk_buff *skb, unsigned int loc);

unsigned int filter_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);


#endif /*_FIREWALL_RULES_H*/