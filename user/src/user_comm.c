#include "user_comm.h"

/**
 * @brief:与内核进行通信
 * @param:消息内容
 * @param:消息长度
 * @return:内核响应
 */
struct KernelResp ComWithKernel(void *smsg, unsigned int slen)
{
    struct sockaddr_nl local;
    struct sockaddr_nl target;
    struct KernelResp rsp;
    int data_len, targetlen = sizeof(struct sockaddr_nl);
    /**
     * 创建一个套接字
     * PF_NETLINK 是套接字协议族，用于指定使用Netlink协议族的套接字。
     * SOCK_RAW 是套接字类型，指定使用原始套接字，以便可以直接访问底层协议。
     * NETLINK_MYFW 是自定义的Netlink协议标识符，用于识别特定的Netlink协议。
     */
    int skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYFW);
    // 套接字创建失败
    if (skfd < 0)
    {
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    /**
     * 初始化local结构体并设置了Netlink套接字的本地地址
     * local.nl_family = AF_NETLINK;：将nl_family成员设置为AF_NETLINK，表示使用Netlink协议族。
     * local.nl_pid = getpid();：将nl_pid成员设置为当前进程的PID，即获取当前进程的进程ID。
     * local.nl_groups = 0;：将nl_groups成员设置为0，表示不加入任何多播组。
     */
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
    // 将netlink套接字与local地址绑定
    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
    {
        close(skfd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    /**
     * 初始化并设置Netlink套接字的目标地址。
     * target.nl_family = AF_NETLINK;：将nl_family成员设置为AF_NETLINK，表示使用Netlink协议族。
     * target.nl_pid = 0;：将nl_pid成员设置为0，表示目标地址为内核空间，因为在Netlink通信中，0表示内核进程。
     * target.nl_groups = 0;：将nl_groups成员设置为0，表示不加入任何多播组。
     */
    memset(&target, 0, sizeof(target));
    target.nl_family = AF_NETLINK;
    target.nl_pid = 0;
    target.nl_groups = 0;
    // 为发送到内核的消息分配内存
    /**
     * LMSG_SPACE用于计算给定数据长度（slen）的Netlink消息所需的总空间大小。
     * NLMSG_SPACE宏会计算出消息头部和数据部分所需的空间，并将其转换为字节数。
     * 使用malloc函数分配足够的内存空间，以存储计算出的消息空间大小。
     * sizeof(uint8_t)是为了确保以字节为单位分配内存。
     */
    struct nlmsghdr *message = (struct nlmsghdr *)malloc(NLMSG_SPACE(slen) * sizeof(uint8_t));
    if (!message)
    {
        close(skfd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 初始化内存
    memset(message, '\0', sizeof(struct nlmsghdr));
    // 设置消息长度
    message->nlmsg_len = NLMSG_SPACE(slen);
    // 设置标志、类型和序列号
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    // 设置消息的源进程号
    message->nlmsg_pid = local.nl_pid;
    // 从smsg中复制slen个字节到message的数据部分
    memcpy(NLMSG_DATA(message), smsg, slen);
    // 通过套接字发送消息
    if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&target, sizeof(target)))
    {
        close(skfd);
        free(message);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 通过套接字接收消息
    struct nlmsghdr *nl_hd = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD) * sizeof(uint8_t));
    if (!nl_hd)
    {
        close(skfd);
        free(message);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    if (!recvfrom(skfd, nl_hd, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *)&target, (socklen_t *)&targetlen))
    {
        close(skfd);
        free(message);
        free(nl_hd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 计算数据部分的额长度
    data_len = nl_hd->nlmsg_len - NLMSG_SPACE(0);
    rsp.data = malloc(data_len);
    if (!(rsp.data))
    {
        close(skfd);
        free(message);
        free(nl_hd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    memset(rsp.data, 0, data_len);
    // 将收到的消息nl_hd的data_len个字节复制到rsp的data字段
    memcpy(rsp.data, NLMSG_DATA(nl_hd), data_len);
    rsp.stat = data_len - sizeof(struct KernelResHdr);
    if (rsp.stat < 0)
    {
        rsp.stat = ERROR_CODE_EXCHANGE;
    }
    // 指向响应头
    rsp.header = (struct KernelResHdr *)rsp.data;
    // 指向响应体
    rsp.body = rsp.data + sizeof(struct KernelResHdr);
    close(skfd);
    free(message);
    free(nl_hd);
    return rsp;
}
