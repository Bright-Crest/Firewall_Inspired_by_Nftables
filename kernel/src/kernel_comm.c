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
    // 如果数据部分长度小于用户的请求体的大小
    if (len < /*TODO: sizeof(struct UsrReq)*/)
    {
        PRINTK_WARN("Wrong size of received Netlink message\n");
        return;
    }
    PRINTK_DEBUG("Data is received from user. pid=%d, len=%d\n", pid, len);
    // 取出了源地址、数据和长度，然后处理用户请求
    // TODO: ProcUsrReq(pid, data, len);
}

/**
 * @brief Initialize Netlink socket
 * @details Will be called when the kernel module is inserted
 */
struct sock *netlink_init()
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
void netlink_release()
{
    netlink_kernel_release(nl_sock);
}

/**
 * @param data consists of header and body. Header is `UserMsgHeader`.
 * @return total length of the kernel response
 */
int process_user_request(unsigned int pid, void *data, unsigned int len)
{
    // extract header
    UserMsgHeader *uheader = (UserMsgHeader *)data;
    // Manage *manage = NULL;
    // LogExport *log_export = NULL;
    // UserResponse *uresponse = NULL;

    switch (uheader->type)
    {
    case MANAGE:
        if (len != sizeof(UserMsgHeader) + sizeof(Manage)) {
            // TODO: length not equal, error handle
        }
        // extract body
        Manage *manage = (Manage *)(data + sizeof(UserMsgHeader));
        process_manage(manage);
        // TODO: how to form kernel response
        break;
    case LOG_EXPORT:
        // TODO: case LOG_EXPORT
        break;    
    case USER_RESPONSE:
        // TODO: case USER_RESPONSE 
        break;
    default:
        break;
    }

    // TODO: Kernel response
    return 0;
}

void process_manage(Manage *manage)
{
    switch (manage->hierarchy)
    {
    case TABLE:
        manage_table(manage->data.table, manage->operation.table_op);
        break;
    case CHAIN:
        manage_chain(manage->data.chain, manage->operation.chain_op, manage->table_name);
        break;
    case RULE:
        manage_rule(manage->data.rule, manage->operation.rule_op, manage->table_name, manage->chain_name);
        break;
    default:
        break;
    }
}
