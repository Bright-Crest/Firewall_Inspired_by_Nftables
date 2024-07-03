/*rule management*/
#ifndef _FIREWALL_RULE_H
#define _FIREWALL_RULE_H

#include "common.h"

// copied from <linux/netfilter.h>
enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS,
	NF_INET_INGRESS = NF_INET_NUMHOOKS,
};


// Since the enum values are store in global scope, they have to be globally
// unique. The usual methods to prevent name collision in enum is to add the
// name enum's name as prefix for each of the enum values. 
typedef enum {CHAIN_FILTER, CHAIN_NAT} ChainType;
typedef enum {MATCH_TODO} MatchType;
typedef enum {STMT_VERDICT, STMT_LOG, STMT_COUNTER, STMT_NAT, STMT_CONNTRACK} StmtType;

typedef enum {VERDICT_ACCEPT, VERDICT_DROP, VERDICT_CONTINUE, VERDICT_RETURN, VERDICT_JUMP, VERDICT_GOTO} VerdictStmtType;

typedef enum {CP_TODO} ChainPriority;
typedef enum {CHAIN_ACCEPT, CHAIN_DROP} ChainPolicy;
typedef enum {MATCH, NOT_MATCH} MatchResult;

typedef unsigned int Handle;


struct Table;
struct Chain;
struct Rule;
struct Match;
struct Stmt;

struct FilterChain;

struct VerdictStmt;


typedef struct Table Table;
typedef struct Chain Chain;
typedef struct Rule Rule;
typedef struct Match Match;
typedef struct Stmt Stmt;

typedef struct FilterChain FilterChain;

typedef struct VerdictStmt VerdictStmt;


struct Table {
  Name name;
  Comment comment;
  // Chains
};

struct Chain {
  Name name;
  ChainType type;
  enum nf_inet_hooks hook;
  ChainPriority priority;
  ChainPolicy policy;
  Comment comment;
  // Rules
  void *chain;
  void (*instantiate)(Chain *self, Argument *, ReturnT *);
};

struct Rule {
  Handle handle;
  Comment comment;
  // Matches
  Stmt *stmt;
};

struct Match {
  MatchType type;
  void *match;
  MatchResult (*instantiate)(Match *self, Argument *);
};

struct Stmt {
  StmtType type;
  void *stmt;
  void (*instantiate)(Stmt *self, Argument *, ReturnT *);
};


struct FilterChain {
  // TODO: filter
};


struct VerdictStmt {
  VerdictStmtType type;
  Name name_for_jump_or_goto;
  void (*instantiate)(VerdictStmt *self, Argument *, ReturnT *);
};


void chain_instantiate(Chain *self, Argument *, ReturnT *);
void stmt_instantiate(Stmt *self, Argument *, ReturnT *);

void verdict_instantiate(VerdictStmt *self, Argument *, ReturnT *);

#endif /*_FIREWALL_RULE_H*/ 
