#define DEFAULT_ACTION 0

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

// TODO: rename and maybe include `NATRule` in share/include/share.h
struct NATRule
{
    unsigned int saddr; // 源IP
    unsigned int smask; // 源IP的掩码
    unsigned int daddr; // 转换后的IP
    unsigned short sport;   // 原始端口
    unsigned short dport;   // 转换后的端口
    unsigned short nowPort; // 当前使用的端口
    struct NATRule *next;
};

// TODO: rename and maybe include `FTRule` in share/include/share.h
struct FTRule
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
    struct FTRule *next;
};

unsigned int ftrule_match(struct sk_buff *skb, struct FTRule *rule);

unsigned int filter_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);

unsigned int snat_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);

unsigned int dnat_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);


