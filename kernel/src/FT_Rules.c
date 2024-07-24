#include "core.h"
#include "rules.h"

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

static DEFINE_RWLOCK(RuleLock);

static struct FTRule_Chain *Table_head = NULL;
 
int ftrule_match(struct sk_buff *skb, unsigned int loc)
{
    int islog = 1;
    int ismatch = -1;
    struct connSess *node;
    // 用于遍历规则链表
    struct FilterRule *tmp, *rule;
    // 获取ip头
    struct iphdr *hdr = ip_hdr(skb);
    // 传输层报文头
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    // 源ip和目的ip，并从网络字节顺序转为主机字节顺序
    unsigned int sip = ntohl(hdr->saddr);
    unsigned int tip = ntohl(hdr->daddr);
    // 源端口和目的端口
    unsigned short src_port, dst_port;
    unsigned int issyn = 0;
    // 协议
    u_int8_t proto = hdr->protocol;
    switch (proto)
    {
        // 传输层协议为tcp
    case IPPROTO_TCP:
        tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
        src_port = ntohs(tcpHeader->source);
        dst_port = ntohs(tcpHeader->dest);
        // 检查是否存在syn位
        issyn = (tcpHeader->syn) ? 1 : 0;
        break;
        // 传输层协议为udp
    case IPPROTO_UDP:
        udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
        src_port = ntohs(udpHeader->source);
        dst_port = ntohs(udpHeader->dest);
        break;
        // ICMP
    // case IPPROTO_ICMP:
    // 默认情况
    default:
        src_port = 0;
        dst_port = 0;
        break;
    }
    // 遍历规则链表
    // 上锁
    read_lock(&RuleLock);
    struct FilterRule *new_rule, *chain_head;
    struct FTRule_Chain *chain_tmp;
    for (chain_tmp = Table_head; chain_tmp != NULL; chain_tmp = chain_tmp->next)
    {
            if ((chain_tmp->applyloc&loc) != 0)
            {
                chain_head=chain_tmp->chain_head;
                for (tmp = chain_head; tmp != NULL; tmp = tmp->next)
                {
                    // 匹配到一条规则
                    if (((sip & tmp->smask) == (tmp->saddr & tmp->smask) || tmp->saddr == 0 || (sip) == (tmp->saddr)) &&
                        (((tip) == (tmp->taddr)) ||
                        ((tip & tmp->tmask) == (tmp->taddr & tmp->tmask))) &&
                        (src_port >= ((unsigned short)(tmp->sport >> 16)) && src_port <= ((unsigned short)(tmp->sport & 0xFFFFu))) &&
                        (dst_port >= ((unsigned short)(tmp->tport >> 16)) && dst_port <= ((unsigned short)(tmp->tport & 0xFFFFu))) &&
                        (tmp->protocol == IPPROTO_IP || tmp->protocol == proto))
                    {
                        if (tmp->act == NF_ACCEPT)
                        {
                            ismatch = 1;
                            // TODO: 添加连接
                            // addConn(sip, tip, src_port, dst_port, proto, islog, issyn);
                            read_unlock(&RuleLock);
                            return ismatch;
                        }
                        else
                        {
                            ismatch = 0;
                            read_unlock(&RuleLock);
                            read_unlock(&RuleLock);
                            return ismatch;
                        }

                        // 赋值匹配到的规则
                        rule = tmp;
                        break;
                    }
                }
        }
    }

    // 解锁
    read_unlock(&RuleLock);
    read_unlock(&RuleLock);
    if (ismatch == -1 && DEFAULT_ACTION == NF_ACCEPT)
    {
        // TODO: 添加连接
        // addConn(sip, tip, src_port, dst_port, proto, islog, issyn);
    }
    return ismatch;
}


unsigned int filter_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
    int flag = -1;
    // 接收匹配到的规则
    struct FilterRule rule;
    // TODO: &rule: wrong type
    // flag = ftrule_match(skb, &rule);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        printk(KERN_DEBUG "[filter] matching result: %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return DEFAULT_ACTION;
}

unsigned int add_rule(char chain_name[], char after[], struct FilterRule rule)
{
    struct FilterRule *new_rule, *tmp, *chain_head;
    struct FTRule_Chain *chain_tmp;

    // 为新规则分配空间
    // GFP_KERNEL 表示内存分配在进程上下文中进行，
    // 并且请求的内存应该来自内核的内存池（kernel memory pool）。
    // 这意味着内存分配是在内核空间进行的，分配的内存可以由进程在内核中使用。
    new_rule = (struct FilterRule *)kzalloc(sizeof(struct FilterRule), GFP_KERNEL);

    if (new_rule == NULL)
    {
        printk(KERN_WARNING "no memory for new filter rule.\n");
        return 10;
    }
    memcpy(new_rule, &rule, sizeof(struct FilterRule));
    if (new_rule == NULL)
    {
        kfree(new_rule);
        return NULL;
    }
    // 新增规则至规则链表
    write_lock(&RuleLock);
    if (strlen(chain_name)==0)
    {
        printk(KERN_INFO "no chain name provided.\n");
        chain_name="default";
    }

    for (chain_tmp = Table_head; chain_tmp != NULL; chain_tmp = chain_tmp->next)
    {
        if (strcmp(chain_tmp->name, chain_name) == 0)
        {
            chain_head=chain_tmp->chain_head;
            // 如果前序规则名为空
            if (strlen(after) == 0)
            {
                new_rule->next = chain_head;
                chain_head = new_rule;
                write_unlock(&RuleLock);
                write_unlock(&RuleLock);
                return 1;
            }
            // 插入前序规则名之后
            for (tmp = chain_head; tmp != NULL; tmp = tmp->next)
            {
                if (strcmp(tmp->name, after) == 0)
                {
                    new_rule->next = tmp->next;
                    tmp->next = new_rule;
                    write_unlock(&RuleLock);
                    write_unlock(&RuleLock);
                    return 1;
                }
            }    
        }
    }


    
    printk(KERN_INFO "add filter rule failed.\n");
    // 添加失败
    write_unlock(&RuleLock);
    write_unlock(&RuleLock);
    kfree(new_rule);
    return 0;
}

unsigned int addRule_chain(char after[], struct FTRule_Chain chain)
{
    struct FTRule_Chain *new_chain, *tmp;

    new_chain = (struct FTRule_Chain *)kzalloc(sizeof(struct FTRule_Chain), GFP_KERNEL);

    if (new_chain == NULL)
    {
        printk(KERN_WARNING "no memory for new filter rule chain.\n");
        return 10;
    }
    memcpy(new_chain, &rule, sizeof(struct FilterRule));
    if (new_chain == NULL)
    {
        kfree(new_chain);
        return NULL;
    }
    // 新增规则链表
    write_lock(&RuleLock);
    if (Table_head== NULL)
    {
        Table_head = new_chain;
        Table_head->next = NULL;
        write_unlock(&RuleLock);
        write_unlock(&RuleLock);
        return 1;
    }
    // 如果前序规则链表名为空
    if (strlen(after) == 0)
    {
        new_chain->next = Table_head;
        Table_head = new_chain;
        write_unlock(&RuleLock);
        write_unlock(&RuleLock);
        return 1;
    }
    // 插入前序规则链表名之后
    for (tmp = Table_head; tmp != NULL; tmp = tmp->next)
    {
        if (strcmp(tmp->name, after) == 0)
        {
            new_chain->next = tmp->next;
            tmp->next = new_chain;
            write_unlock(&RuleLock);
            write_unlock(&RuleLock);
            return 1;
        }
    }    
        


    
    printk(KERN_INFO "add filter rule chain failed.\n");
    // 添加失败
    write_unlock(&RuleLock);
    write_unlock(&RuleLock);
    kfree(new_chain);
    return 0;

}



unsigned int delRule(char chain_name[],char name[])
{
    // 用于遍历规则链表
    struct FilterRule *new_rule, *tmp, *chain_head;
    struct FTRule_Chain *chain_tmp;
    // 删除的规则个数
    int ret = 0;
    // 上锁
    write_lock(&RuleLock);
    if (strlen(chain_name)==0)
    {
        printk(KERN_INFO "no chain name provided.\n");
        chain_name="default";
    }
    // 遍历
    for (chain_tmp = Table_head; chain_tmp != NULL; chain_tmp = chain_tmp->next)
    {
        if (strcmp(chain_tmp->name, chain_name) == 0)
        {
            chain_head=chain_tmp->chain_head;
            // 如果链表头为 name
            while (chain_head!= NULL && strcmp(chain_head->name, name) == 0)
            {
                struct FilterRule *delRule = chain_head;
                chain_head = chain_head->next;
                kfree(delRule);
                ret++;
            }
            for (tmp = chain_head; tmp != NULL && tmp->next != NULL;)
            {
                // 匹配到一条规则
                if (strcmp(tmp->next->name, name) == 0)
                {
                    // 保存被删除规则的指针
                    struct FilterRule *delRule = tmp->next;
                    // 被删除规则前一个规则的next指针移向next的next
                    tmp->next = tmp->next->next;
                    // 释放被删除指针
                    kfree(delRule);
                    ret++;
                }
                else
                {
                    tmp = tmp->next;
                }
            }   
        }
    }

    
    
    
    
    // 解锁
    write_unlock(&RuleLock);
    write_unlock(&RuleLock);
    return ret;
}

unsigned int delRule_chain(char chain_name[])
{
    struct FTRule_Chain  *tmp;
    // 删除的规则个数
    int ret = 0;
    // 上锁
    write_lock(&RuleLock);
    while (Table_head != NULL && strcmp(Table_head->name, chain_name) == 0)
    {
        struct FTRule_Chain *delRule = Table_head;
        Table_head = Table_head->next;
        kfree(delRule);
        ret++;
    }
    for (tmp = Table_head; tmp != NULL && tmp->next != NULL;)
    {
        // 匹配到一条规则
        if (strcmp(tmp->next->name, chain_name) == 0)
        {
            struct FilterRule *chain_head=tmp->next->chain_head;
            struct FilterRule tmp_rule;
            for (tmp_rule = chain_head; tmp_rule != NULL ;)
            {
                
                // 保存被删除规则的指针
                struct FTRule *delRule = tmp_rule;
                tmp_rule=tmp_rule->next;
                // 释放被删除指针
                kfree(delRule);
                
            } 
            // 保存被删除规则的指针
            struct FTRule_Chain *delRule_chain = tmp->next;
            // 被删除规则前一个规则的next指针移向next的next
            tmp->next = tmp->next->next;
            // 释放被删除指针
            kfree(delRule_chain);
            ret++;
        }
        else
        {
            tmp = tmp->next;
        }
    }
    // 解锁
    write_unlock(&RuleLock);
    write_unlock(&RuleLock);
    return ret;
}
