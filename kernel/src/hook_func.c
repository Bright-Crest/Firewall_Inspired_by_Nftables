/**
 * 钩子函数
 */
#include "hook_func.h"


/**
 * @brief 本地输入
 */
unsigned int NfHookLocalIn(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    int flag;

    flag = ftrule_match(skb, LOCALIN);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return DEFAULT_ACTION;
}

/*******************************************************
 * @brief 本地出站
 *
 * @param priv
 * @param skb
 * @param state
 * @return unsigned int
 *******************************************************/
unsigned int NfHookLocalOut(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int flag;
    flag = ftrule_match(skb, LOCALOUT);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return NF_ACCEPT;
}


unsigned int NfHookPreRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int flag;
    flag = ftrule_match(skb, PREROUTING);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return NF_ACCEPT;
}

unsigned int NfHookForward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int flag;
    flag = ftrule_match(skb, FORWARD);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return NF_ACCEPT;
}

unsigned int NfHookPostRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int flag;
    flag = ftrule_match(skb, POSTROUTING);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return NF_ACCEPT;
}
