#ifndef _DATA_H
#define _DATA_H
#include <linux_dep.h>


#define MAXRuleNameLen 32 // 规则名称最大长度

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

//response defination
#define ERR -1
#define RETURN_LOG_INFO 10


//user

struct FT_RULE
{
    char name[MAXRuleNameLen + 1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int taddr;
    unsigned int tmask;
    unsigned int sport;
    unsigned int tport;
    u_int8_t protocol;
    unsigned int act;
    unsigned int islog;
};

struct NAT_RULE
{
    unsigned int saddr; // 源IP
    unsigned int smask; // 源IP的掩码
    unsigned int daddr; // 转换后的IP

    unsigned short sport;   // 原始端口
    unsigned short dport;   // 转换后的端口
    unsigned short nowPort; // 当前使用的端口
};
struct UsrReq
{
    unsigned int tp;
    char ruleName[MAXRuleNameLen + 1];
    // 请求体——过滤规则、NAT规则、默认动作
    union
    {
        struct FTRule FTRule;
        struct NATRule NATRule;
        unsigned int defaultAction;
        unsigned int num;
    } msg;
};



//kernel
//
struct FT_RULE_NODE
{
    FT_RULE data;
    FT_RULE_NODE* next;
};

struct NAT_RULE_NODE
{
    NAT_RULE data;
    NAT_RULE_NODE* next;
};

struct RULE_CHAIN
{
    unsigned int node_type;
    void* node_root;
};


struct KernelResHdr
{
    unsigned int bodyTp; // 响应体的类型
    unsigned int arrayLen;
};

struct KernelResp
{
    int stat;                    // 状态码
    void* data;                  // 回应包指针，记得free
    struct KernelResHdr* header; // 不要free；指向data中的头部
                     // 不要free；指向data中的Body
};



