/**
 * @file share.h
 * @author Bright-Crest (stephenzhu2004@163.com)
 * @brief Common data types can be shared by both kernel and user
 * @date 2024/07
 */

#ifndef _FIREWALL_SHARE_H
#define _FIREWALL_SHARE_H

#define MAX_MATCH 10 // per rule
#define MAX_STMT 10 // per rule
#define MAX_NAME_LENGTH 30
#define MAX_COMMENT_LENGTH 100

#define LOCALIN 0b00001
#define PREROUTING 0b00010
#define FORWARD 0b00100
#define POSTROUTING 0b01000
#define LOCALOUT 0b10000

// TODO: use kernel built-in definitions
#define PROTOCOL_ANY 0
#define PROTOCOL_PING 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#ifndef NF_INET_PRE_ROUTING // in user space
// copied from <linux/netfilter.h> but renamed
// typedef enum {
// 	NF_INET_PRE_ROUTING,
// 	NF_INET_LOCAL_IN,
// 	NF_INET_FORWARD,
// 	NF_INET_LOCAL_OUT,
// 	NF_INET_POST_ROUTING,
// 	NF_INET_NUMHOOKS,
// 	NF_INET_INGRESS = NF_INET_NUMHOOKS,
// } HookPoint;
typedef int HookPoint;
#else // in kernel space
typedef enum nf_inet_hooks HookPoint;
#endif

typedef char Name[MAX_NAME_LENGTH + 1];
typedef char Comment[MAX_COMMENT_LENGTH + 1];

// TODO: 与用户态统一
#define ADD 0
#define DELETE 1
#define DESTROY 2
#define LIST 3
#define FLUSH 4
#define CREATE 5
#define RENAME 6
#define INSERT 7
#define REPLACE 8
#define RESET 9
// typedef enum {ADD, DELETE, DESTROY, LIST, FLUSH} TableChangeType;
// typedef enum {ADD, DELETE, DESTROY, LIST, FLUSH, CREATE, RENAME} ChainChangeType;
// typedef enum {ADD, DELETE, DESTROY, INSERT = 7, REPLACE, RESET} RuleChangeType;
typedef int TableChangeType;
typedef int ChainChangeType;
typedef int RuleChangeType;

// Since the enum values are store in global scope, they have to be globally
// unique. The usual methods to prevent name collision in enum is to add the
// name enum's name as prefix for each of the enum values. 

// Top level types.
typedef enum {CHAIN_FILTER, CHAIN_NAT} ChainType;
typedef enum {MATCH_IP, MATCH_TCP} MatchType;
typedef enum {STMT_VERDICT, STMT_LOG, STMT_COUNTER, STMT_NAT, STMT_CONNTRACK} StmtType;

// Second level types.
typedef enum {VERDICT_ACCEPT, VERDICT_DROP, VERDICT_CONTINUE, VERDICT_RETURN, VERDICT_JUMP, VERDICT_GOTO} VerdictStmtType;

// Other useful types.
typedef enum {CP_CONNTRACK = -200, CP_DSTNAT = -100, CP_FILTER = 0, CP_SRCNAT = 100, } ChainPriority;
typedef enum {CHAIN_ACCEPT, CHAIN_DROP} ChainPolicy;
typedef enum {MATCH = 1, NOT_MATCH = 0} MatchResult;

typedef unsigned int Handle;

// used for communication
// like a mirror of core.h

// imported

/**
 * @brief:内核接受的过滤规则
 */
struct FTRule
{
    char name[MAX_NAME_LENGTH + 1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int taddr;
    unsigned int tmask;
    unsigned int sport;
    unsigned int tport;
    unsigned int protocol;
    unsigned int act;
    unsigned int islog;
};

/**
 * @brief:内核接受的nat规则
 */
struct NATRule
{
    unsigned int saddr; // 记录：原始IP | 规则：原始源IP
    unsigned int smask; // 记录：无作用  | 规则：原始源IP掩码
    unsigned int daddr; // 记录：转换后的IP | 规则：NAT 源IP

    unsigned short sport;   // 记录：原始端口 | 规则：最小端口范围
    unsigned short dport;   // 记录：转换后的端口 | 规则：最大端口范围
    unsigned short nowPort; // 记录：当前使用端口 | 规则：无作用
    struct NATRule *next;
};

struct ConnLog
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int protocol;
    int natType;
    struct NATRule nat; // NAT记录
};

struct FilterRule_Chain
{
    char name[MAX_NAME_LENGTH + 1];
    unsigned int applyloc;
};

// second level matches

typedef struct {
  unsigned int protocol; ///< Equal to the default value means not to match, i.e. accepting all packets.
  int is_length_exclude; ///< 0: in the interval; 1: exclude the interval
  unsigned int min_length;
  unsigned int max_length; ///< The max value of the total packet length of the interval. This aims to support matching intervals. See `MATCH_INTERVAL`.
  int is_saddr_exclude;
  unsigned int min_saddr;
  unsigned int max_saddr; ///< Source address
  int is_daddr_exclude;
  unsigned int min_daddr;
  unsigned int max_daddr; ///< Destination address
  int is_sport_exclude;
  unsigned int min_sport;
  unsigned int max_sport;
  int is_dport_exclude;
  unsigned int min_dport;
  unsigned int max_dport;
} IPMatchT;

// second level stmts

typedef struct {
  VerdictStmtType type;
  Name name_for_jump_or_goto;
} VerdictStmtT;

// TODO: other `Stmt`s

// match & stmt

typedef struct {
  MatchType type;
  union {
    IPMatchT ipm;
    // TODO: other `Match`es
  } match;
} MatchT;

typedef struct {
  StmtType type;
  union {
    VerdictStmtT verdict;
    // TODO: other `Stmt`s
  } stmt;
} StmtT;

// second level chains

typedef struct {
  ChainPolicy policy;
} FilterChainT;

typedef struct {
  // TODO: NatChainT
} NatChainT;

// top level structs

typedef struct {
  Name name;
  Comment comment;
} TableT;

typedef struct {
  Name name;
  ChainType type;
  HookPoint hook;
  ChainPriority priority;
  Comment comment;
  union {
    FilterChainT filter;
    NatChainT nat;
  } chain;
} ChainT;

typedef struct {
  Handle handle;
  Comment comment;
  MatchT matches[MAX_MATCH];
  StmtT stmts[MAX_STMT];
} RuleT;

#endif /*_FIREWALL_SHARE_H*/
