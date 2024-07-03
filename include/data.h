#ifndef _DATA_H
#define _DATA_H
#include <linux_dep.h>


#define MAXRuleNameLen 32 // ����������󳤶�

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
    unsigned int saddr; // ԴIP
    unsigned int smask; // ԴIP������
    unsigned int daddr; // ת�����IP

    unsigned short sport;   // ԭʼ�˿�
    unsigned short dport;   // ת����Ķ˿�
    unsigned short nowPort; // ��ǰʹ�õĶ˿�
};
struct UsrReq
{
    unsigned int tp;
    char ruleName[MAXRuleNameLen + 1];
    // �����塪�����˹���NAT����Ĭ�϶���
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
    unsigned int bodyTp; // ��Ӧ�������
    unsigned int arrayLen;
};

struct KernelResp
{
    int stat;                    // ״̬��
    void* data;                  // ��Ӧ��ָ�룬�ǵ�free
    struct KernelResHdr* header; // ��Ҫfree��ָ��data�е�ͷ��
                     // ��Ҫfree��ָ��data�е�Body
};



