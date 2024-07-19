#ifndef _FIREWALL_SHARE_H
#define _FIREWALL_SHARE_H

#define MAX_MATCH 10 // per rule
#define MAX_STMT 10 // per rule
#define MAX_NAME_LENGTH 30
#define MAX_COMMENT_LENGTH 100

typedef char Name[MAX_NAME_LENGTH + 1];
typedef char Comment[MAX_COMMENT_LENGTH + 1];

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

// TODO:

// second level stmts

typedef struct {
  VerdictStmtType type;
  Name name_for_jump_or_goto;
} VerdictStmtT;

// TODO: 

// match & stmt

typedef struct {
  MatchType type;
  union {
    // TODO:
  } match;
} MatchT;

typedef struct {
  StmtType type;
  union {
	VerdictStmtT verdict;
	// TODO:
  } stmt;
} StmtT;

// second level chains

typedef struct {
  // TODO:
} FilterChainT;

typedef struct {
  // TODO:
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
  ChainPolicy policy;
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
