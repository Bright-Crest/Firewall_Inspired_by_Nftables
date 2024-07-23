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

#define LOCALIN 0b00001
#define PREROUTING 0b00010
#define FORWARD 0b00100
#define POSTROUTING 0b01000
#define LOCALOUT 0b10000

#define MAX_NAME_LENGTH 32 // 规则名称最大长度

#define DEFAULT_ACTION NF_ACCEPT

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

struct FTRule_Chain
{
    char name[MAX_NAME_LENGTH+ 1];
    FTRule *chain_head;
    FTRule_Table *next;
    unsigned int applyloc=LOCALIN|LOCALOUT;
};

static struct FTRule_chain *Table_head= NULL;

unsigned int add_rule(char chain_name[], char after[], struct FTRule rule);

unsigned int addRule_chain(char after[], struct FTRule_Chain chain);

unsigned int delRule(char chain_name[],char name[]);

unsigned int delRule_chain(char chain_name[]);

unsigned int ftrule_match(struct sk_buff *skb, unsigned int loc);

unsigned int filter_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);



