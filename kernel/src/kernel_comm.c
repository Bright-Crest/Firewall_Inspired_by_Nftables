#include "kernel_comm.h"

// 创建一个套接字结构
static struct sock *nl_sock = NULL;

/**
 * @brief Send data from kernel to user using Netlink
 */
int send(unsigned int pid, void *data, unsigned int len)
{
    int ret;
    // netlink套接字消息头
    struct nlmsghdr *nl_hd;
    // 套接字缓冲区
    struct sk_buff *skb;
    // 创建一个新的 netlink 消息缓冲区。
    skb = nlmsg_new(len, GFP_ATOMIC);
    if (skb == NULL)
    {
        PRINTK_WARN("Fail to allocating a new socket buffer\n");
        return -1;
    }
    // 向netlink消息缓冲区中添加netlink消息头
    nl_hd = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
    // 将data复制到netlink消息数据中
    memcpy(NLMSG_DATA(nl_hd), data, len);
    // 设置目标组
    // 会将消息发送给所有正在监听 netlink 套接字的接收者。
    NETLINK_CB(skb).dst_group = 0;
    // 将netlink消息发送给指定的接收者
    ret = netlink_unicast(nl_sock, skb, pid, MSG_DONTWAIT);
    PRINTK_DEBUG("Data is sended to user. pid=%d, len=%d, ret=%d\n", pid, nl_hd->nlmsg_len - NLMSG_SPACE(0), ret);
    return ret;
}
/**
 * @brief Send header and body from kernel to user using Netlink
 */
// int send(unsigned int pid, void *header, void *body, unsigned int header_len, unsigned int body_len)
// {
//     unsigned int len = header_len + body_len;
//     int ret;
//     // netlink套接字消息头
//     struct nlmsghdr *nl_hd;
//     // 套接字缓冲区
//     struct sk_buff *skb;
//     // 创建一个新的 netlink 消息缓冲区。
//     skb = nlmsg_new(len, GFP_ATOMIC);
//     if (skb == NULL)
//     {
//         PRINTK_WARN("Fail to allocating a new socket buffer\n");
//         return -1;
//     }
//     // 向netlink消息缓冲区中添加netlink消息头
//     nl_hd = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
//     // 复制到netlink消息数据中
//     memcpy(NLMSG_DATA(nl_hd), header, header_len);
//     memcpy(NLMSG_DATA(nl_hd) + header_len, body, body_len);
//     // 设置目标组
//     // 会将消息发送给所有正在监听 netlink 套接字的接收者。
//     NETLINK_CB(skb).dst_group = 0;
//     // 将netlink消息发送给指定的接收者
//     ret = netlink_unicast(nl_sock, skb, pid, MSG_DONTWAIT);
//     PRINTK_DEBUG("Data is sended to user. pid=%d, len=%d, ret=%d\n", pid, nl_hd->nlmsg_len - NLMSG_SPACE(0), ret);
//     return ret;
// }
/**
 * @brief Receive data from user in kernel based on Netlink
 * @param struct sk_buff *skb，in the path linux/include/linux/skbuff.h line 687
 */
void receive(struct sk_buff *skb)
{
    void *data;
    // NETLINK套接字消息头
    struct nlmsghdr *nl_hd = NULL;
    unsigned int pid, len;
    // 利用nlmsg_hdr获取skb中指向netlink消息头部的指针
    nl_hd = nlmsg_hdr(skb);
    if ((nl_hd->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nl_hd->nlmsg_len))
    {
        PRINTK_WARN("Illegal received Netlink message\n");
        return;
    }
    // 利用NLMSG_DATA从netlink消息中获取指向数据消息的指针
    data = NLMSG_DATA(nl_hd);
    // 获取来源进程的pid
    pid = nl_hd->nlmsg_pid;
    // 计算数据部分的长度
    len = nl_hd->nlmsg_len - NLMSG_SPACE(0);

    PRINTK_DEBUG("Data is received from user. pid=%d, len=%d\n", pid, len);
    // 取出了源地址、数据和长度，然后处理用户请求
    process_user_request(pid, data, len);
    PRINTK_DEBUG("Finish processing the user request.\n");
}

/**
 * @brief Initialize Netlink socket
 * @details Will be called when the kernel module is inserted
 */
struct sock *netlink_init(void)
{
    /**
     * struct netlink_kernel_cfg, in the path linux/include/linux/netlink.h line 44
     */
    struct netlink_kernel_cfg nl_conf = {
        // 指定了一个回调函数，用于在接收到 netlink 消息时进行处理
        // void (*input)(struct sk_buff *skb);
        .input = receive,
    };
    /**
     * 函数的第一个参数 net 是指定关联的网络命名空间，一般使用 &init_net。
     * 第二个参数用于标识 netlink 套接字的协议类型，这里使用自定义的协议。
     * 第三个参数nl_conf是一个指向netlink_kernel_cfg结构体的指针，用于配置netlink套接字的行为。
     */
    nl_sock = netlink_kernel_create(&init_net, NETLINK_MYFW, &nl_conf);
    if (!nl_sock)
    {
        PRINTK_WARN("Fail to create a Netlink socket\n");
        return NULL;
    }
    PRINTK_DEBUG("Success in creating a Netlink socket. socket = %p\n", nl_sock);
    return nl_sock;
}
/**
 * @brief:释放套接字
 */
void netlink_release(void)
{
    netlink_kernel_release(nl_sock);
}

/**
 * @param data consists of header and body. Header is `UserMsgHeader`.
 * @return total length of the kernel response
 */
unsigned int process_user_request(unsigned int pid, void *data, unsigned int len)
{
    PRINTK_DEBUG("Start processing the user request.\n");
    // extract header
    // UserMsgHeader *uheader = (UserMsgHeader *)data;
    struct KernelResHdr *rsp_hdr;
    unsigned int rsp_len = 0;

    // switch (uheader->type)
    switch(MANAGE)
    {
    case MANAGE:
        // if (len != sizeof(UserMsgHeader) + sizeof(Manage)) {
        // if (len != sizeof(Manage)) {
        if (len != sizeof(struct UsrReq)) {
            // TODO: length not equal, error handle
            PRINTK_ERR("Wrong message length.\n");
            PRINTK_DEBUG("len: %d", len);
            rsp_len = sendmsg(pid, "Error in communicating with kernel.\n");
            return rsp_len;
        }
        // extract body
        // Manage *manage = (Manage *)(data + sizeof(UserMsgHeader));
        Manage *manage = (Manage *)data;
        process_manage(pid, manage);
        // TODO: how to form kernel response
        break;
    case LOG_EXPORT:
        // TODO: case LOG_EXPORT
        break;    
    case USER_RESPONSE:
        // TODO: case USER_RESPONSE 
        break;
    default:
        PRINTK_WARN("Unexpected type of the user request.\n");
        // PRINTK_DEBUG("Type: %d", uheader->type);
        rsp_len = sendmsg(pid, "Unexpected type of the request.\n");
        break;
    }

    // TODO: Kernel response
    return len;
}

void process_manage(unsigned int pid, Manage *manage)
{
    PRINTK_DEBUG("Start processing `Manage`.\n");
    struct KernelResHdr *rsp_hdr;
    unsigned int rsp_len = 0;

    // switch (manage->hierarchy)
    switch (USR_REQ)
    {
    case TABLE:
        manage_table(&manage->data.table, manage->operation.table_op);
        break;
    case CHAIN:
        manage_chain(&manage->data.chain, manage->operation.chain_op, manage->table_name);
        break;
    case RULE:
        manage_rule(&manage->data.rule, manage->operation.rule_op, manage->table_name, manage->chain_name);
        break;
    case USR_REQ:
        // struct UsrReq *req = &manage->data.usr_req;
        struct UsrReq *usr_req = (struct UsrReq *)manage;
        manage_usr_req(pid, usr_req);
        break;
    default:
        PRINTK_WARN("Unexpected hierarchy to manage.\n");
        // PRINTK_DEBUG("Hierarchy: %d.\n", manage->hierarchy);
        rsp_len = sendmsg(pid, "Unexpected operation.\n");
        break;
    }
}

void manage_usr_req(unsigned int pid, struct UsrReq *req)
{
    PRINTK_DEBUG("Start processing `UsrReq`.\n");
    int ret;
    struct KernelResHdr *rsp_hdr;
    unsigned int rsp_len = 0;

    switch (req->tp)
    {
    case REQ_ADDFTRULE:
        struct FTRule *_r = &req->msg.FTRule;
        struct FilterRule rule = { 
            .name = {*_r->name},
            .saddr = _r->saddr,
            .smask = _r->smask,
            .taddr = _r->taddr,
            .tmask = _r->tmask,
            .sport = _r->sport,
            .tport = _r->tport,
            .protocol = _r->protocol,
            .act = _r->act,
            .islog = _r->islog
        };
        // strncpy(rule.name, _r->name, MAX_NAME_LENGTH);
        ret = add_rule(req->chain_name, req->name, rule);

        switch (ret)
        {
        case 10:
        case 0:
            rsp_len = sendmsg(pid, "Fail to add a new filter rule.\n");
            break; 
        case 1:
            rsp_len = sendmsg(pid, "Add a new filter rule successfully.\n");
            break;
        default:
            break;
        }
        break;
    case REQ_DELFTRULES:
        ret = delRule(req->chain_name, req->name);

        if (ret <= 0) {
            rsp_len = sendmsg(pid, "Fail to delete the rule.\n");
            break;
        }

        rsp_len = sizeof(struct KernelResHdr);
        rsp_hdr = (struct KernelResHdr *)kzalloc(rsp_len, GFP_KERNEL);
        if (rsp_hdr == NULL) {
            PRINTK_ERR("Kernel kzalloc KernelResHdr failed\n");
            break;
        }
        rsp_hdr->bodyTp = RSP_NULL;
        rsp_hdr->arrayLen = ret;
        send(pid, rsp_hdr, rsp_len);
        kfree(rsp_hdr);
        break;
    case REQ_ADDFTCHAIN:
        struct FilterRule_Chain *_c = &req->msg.chain;
        struct FTRule_Chain chain = {
            .name = {*_c->name},
            .applyloc = _c->applyloc
        };
        PRINTK_DEBUG("Finish copying UsrReq data.\n");
        ret = addRule_chain(req->name, chain);
        PRINTK_DEBUG("Finish adding a chain but it may not be successful.\n");

        switch (ret)
        {
        case 10:
        case 0:
            rsp_len = sendmsg(pid, "Fail to add a new filter chain.\n");
            break; 
        case 1:
            PRINTK_DEBUG("Add a new filter chain successfully.\n");
            rsp_len = sendmsg(pid, "Add a new filter chain successfully.\n");
            break;
        default:
            break;
        }
        break;
    case REQ_DELFTCHAIN:
        ret = delRule_chain(req->name);

        if (ret <= 0) {
            rsp_len = sendmsg(pid, "Fail to delete the chain.\n");
            break;
        }

        rsp_len = sizeof(struct KernelResHdr);
        rsp_hdr = (struct KernelResHdr *)kzalloc(rsp_len, GFP_KERNEL);
        if (rsp_hdr == NULL) {
            PRINTK_ERR("Kernel kzalloc KernelResHdr failed\n");
            break;
        }
        rsp_hdr->bodyTp = RSP_NULL;
        rsp_hdr->arrayLen = ret;
        send(pid, rsp_hdr, rsp_len);
        kfree(rsp_hdr);
        break;
    case REQ_GETAllFTRULES:
        break;
    case REQ_GETALLFTCHAINS:
        break;
    // TODO: other cases
    default:
        PRINTK_WARN("Unexpected UsrReq type.\n");
        PRINTK_DEBUG("UsrReq type: %d.\n", req->tp);
        rsp_len = sendmsg(pid, "Unexpected operation of user request.\n");
        break;
    }

    return; 
}

/**
 * @brief:发送消息到用户层
 * @param:pid，用户进程id
 * @param:msg，发送的消息
 * @return:内核响应长度
 */
int sendmsg(unsigned int pid, const char *msg)
{
    // 分配空间
    void *mem;
    unsigned int rsp_len;
    struct KernelResHdr *rsp_hdr;
    rsp_len = sizeof(struct KernelResHdr) + strlen(msg) + 1;
    mem = kzalloc(rsp_len, GFP_ATOMIC);
    if (mem == NULL)
    {
        PRINTK_WARN("sendmsg kzalloc fail.\n");
        return 0;
    }
    // 构造响应数据包
    rsp_hdr = (struct KernelResHdr *)mem;
    rsp_hdr->bodyTp = RSP_MSG;
    rsp_hdr->arrayLen = strlen(msg);
    memcpy(mem + sizeof(struct KernelResHdr), msg, strlen(msg));
    // 发送响应
    send(pid, mem, rsp_len);
    // 释放内存
    kfree(mem);
    return rsp_len;
}
