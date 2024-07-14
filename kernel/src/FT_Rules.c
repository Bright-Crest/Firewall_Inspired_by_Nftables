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

int ftrule_match(struct sk_buff *skb, struct FTRule *rule)
{
    int islog = 1;
    int ismatch = -1;
    struct connSess *node;
    // 用于遍历规则链表
    struct FTRule *tmp;
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
    read_lock(&FTRuleLock);
    for (tmp = FTRuleHd; tmp != NULL; tmp = tmp->next)
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
                // 添加连接
                addConn(sip, tip, src_port, dst_port, proto, islog, issyn);
            }
            else
            {
                ismatch = 0;
            }

            // 赋值匹配到的规则
            rule = tmp;
            break;
        }
    }
    // 解锁
    read_unlock(&FTRuleLock);
    if (ismatch == -1 && DEFAULT_ACTION == NF_ACCEPT)
    {
        // 添加连接
        addConn(sip, tip, src_port, dst_port, proto, islog, issyn);
    }
    return ismatch;
}


unsigned int filter_op(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
    int flag;
    // 接收匹配到的规则
    struct FTRule rule;
    flag = ftrule_match(skb, &rule);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        printk(KERN_DEBUG "[filter] matching result: %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return DEFAULT_ACTION;
}

