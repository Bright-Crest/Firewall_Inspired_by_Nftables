/**
 * @file comm_protocol.h
 * @author Bright-Crest (stephenzhu2004@163.com)
 * @brief The communication protocol shared by both kernel and user
 * @date 2024/07
 */

#ifndef _FIREWALL_COMM_PROTOCOL_H
#define _FIREWALL_COMM_PROTOCOL_H

#include "share.h"

#define NETLINK_MYFW 17

typedef enum {MANAGE, LOG_EXPORT, USER_RESPONSE} UserMsgType;
typedef enum {TABLE, CHAIN, RULE, USR_REQ} Hierarchy;


// user to kernel

// one uniform header
typedef struct {
  UserMsgType type;
} UserMsgHeader;

/**
 * @brief:用户层的请求结构
 */
struct UsrReq
{
    // 请求类型
    unsigned int tp;
    // 前序规则名
    char ruleName[MAX_NAME_LENGTH + 1];
    // 请求体——过滤规则、NAT规则、默认动作
    union
    {
        struct FTRule FTRule;
        struct NATRule NATRule;
        unsigned int defaultAction;
        unsigned int num;
    } msg;
};

// body

typedef struct {
  Hierarchy hierarchy;
  union {
    TableChangeType table_op;
    ChainChangeType chain_op;
    RuleChangeType rule_op;
  } operation;
  union {
    TableT table;
    ChainT chain;
    RuleT rule;
    struct UsrReq usr_req; // temporary solution. Operation is inside. Or use the operation outside.
  } data;
  Name table_name; // used when hierarchy != TABLE
  Name chain_name; // used when hierarchy == RULE
} Manage;

typedef struct {
  // TODO: Add possible configurations (optional)
} LogExport;

/**
 * Used when user receives a log message and used to make kernel send the next
 * log message.
 * 
 * This should be used in a loop after sending `LogExport` because kernel will 
 * not send the next log message if kernel does not receive `UserResponse`.
 */
typedef struct {
} UserResponse;


// kernel to user

/**
 * @brief:内核响应头
 */
struct KernelResHdr
{
    unsigned int bodyTp; // 响应体的类型
    unsigned int arrayLen;
};

/**
 * @brief:内核响应的结构体
 */
struct KernelResp
{
    int stat;                    // 状态码
    void *data;                  // 回应包指针，记得free
    struct KernelResHdr *header; // 不要free；指向data中的头部
    void *body;                  // 不要free；指向data中的Body
};

#endif /*_FIREWALL_COMM_PROTOCOL_H*/