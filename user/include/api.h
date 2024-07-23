#ifndef _API_APP_H
#define _API_APP_H

#include "share.h"
#include "comm_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>

//request defination
#define SHOW_ALL_RULE 1
#define GET_CONN_INFO 2
#define GET_LOG_INFO 3
#define ADD_FT_RULE 11
#define REMOVE_FT_RULE 12
#define SHOW_FT_RULE 13
#define ADD_NAT_RULE 14
#define REMOVE_NAT_RULE 15
#define SHOW_NAT_RULE 16

// TODO: use kernel built-in definitions
#define PROTOCOL_ANY 0
#define PROTOCOL_PING 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

// use `ChainType` in share/include/share.h
// #define CHAIN_TYPE_FILTER 0
// #define CHAIN_TYPE_NAT 1

// use `HookPoint` in share/include/share.h
// #define CHAIN_HOOK_INPUT 0
// #define CHAIN_HOOK_OUTPUT 1

// only used for rules. Use `ChainPolicy` in share/include/share.h for chains.
#define ACTION_DENY 0
#define ACTION_ACCEPT 1

#define uint8_t unsigned char
// 接收消息的最大载荷
#define MAX_PAYLOAD (1024 * 256)

/**
 * @brief:用户输入过滤规则结构
 */
struct ftrule
{
    char name[MAX_NAME_LENGTH + 1]; // 规则名
    char sip[25];                  // 源ip
    char tip[25];                  // 目的ip
    char sport[15];                // 源端口
    char tport[15];                // 目的端口
    char protocol[6];              // 协议
    unsigned int act;              // 对数据包的行为
    unsigned int islog;            // 是否记录日志
};

/**
 * @brief:用户输入nat规则结构
 */
struct natrule
{
    char sip[25];   // nat源地址
    char tip[25];   // nat地址
    char tport[15]; // 端口
    unsigned short portMin;
    unsigned short portMax;
};

/**
 * @brief:用户层与内核通信函数的声明
 */
// rules

struct KernelResp addFtRule(struct ftrule *filter_rule, Name table, Name chain); // 新增过滤规则
struct KernelResp getAllFTRules(void);                   // 获取所有过滤规则
// TODO: delete by name, by handle or by all the values?
struct KernelResp delFTRule(char name[], Name table, Name chain);                // 删除名为name的规则
// struct KernelResp addNATRule(struct natrule *nat_rule, Name table, Name chain);  // 新增nat规则
// struct KernelResp getAllNATRules(void);                  // 获取所有nat规则
// struct KernelResp delNATRule(int seq, Name table, Name chain);                   // 删除序号为seq的nat规则
struct KernelResp setDefaultAction(unsigned int action); // 设置默认行为
struct KernelResp getAllConns(void);                     // 获取所有连接

// chains

struct KernelResp addChain(ChainT *chain, Name table);
struct KernelResp delChain(Name chain, Name table);

/**
 * @brief:格式转换的工具函数
 */
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int IPint2IPstrNoMask(unsigned int ip, char *ipStr);
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr);

struct KernelResp ComWithKernel(void *header, void *smsg, unsigned int header_len, unsigned int slen);

#endif