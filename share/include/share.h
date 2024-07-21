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

typedef char Name[MAX_NAME_LENGTH + 1];
typedef char Comment[MAX_COMMENT_LENGTH + 1];

// TODO: 与用户态统一
typedef enum {ADD, DELETE, DESTROY, LIST, FLUSH} TableChangeType;
typedef enum {ADD, DELETE, DESTROY, LIST, FLUSH, CREATE, RENAME} ChainChangeType;
typedef enum {ADD, DELETE, DESTROY, INSERT = 7, REPLACE, RESET} RuleChangeType;

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
typedef enum {CP_TODO} ChainPriority;
typedef enum {CHAIN_ACCEPT, CHAIN_DROP} ChainPolicy;
typedef enum {MATCH = 1, NOT_MATCH = 0} MatchResult;

typedef unsigned int Handle;

// copied from <linux/netfilter.h> but renamed
typedef enum {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS,
	NF_INET_INGRESS = NF_INET_NUMHOOKS,
} HookPoint;

// used for communication
// like a mirror of core.h

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
