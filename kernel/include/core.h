// The core and hierarchy of rule management.

#ifndef _FIREWALL_RULE_H
#define _FIREWALL_RULE_H

#include "common.h"

#include <linux/netfilter.h>
#include <linux/list.h>       // for doubly linked list

// copied from <linux/netfilter.h>
// enum nf_inet_hooks {
// 	NF_INET_PRE_ROUTING,
// 	NF_INET_LOCAL_IN,
// 	NF_INET_FORWARD,
// 	NF_INET_LOCAL_OUT,
// 	NF_INET_POST_ROUTING,
// 	NF_INET_NUMHOOKS,
// 	NF_INET_INGRESS = NF_INET_NUMHOOKS,
// };

// pre-definitions
struct Table;
struct Chain;
struct Rule;
struct Match;
struct Stmt;

struct FilterChain;

struct VerdictStmt;


// make it simpler
typedef struct Table Table;
typedef struct Chain Chain;
typedef struct Rule Rule;
typedef struct Match Match;
typedef struct Stmt Stmt;

typedef struct FilterChain FilterChain;

typedef struct VerdictStmt VerdictStmt;


// Top level structs.

/**
 * Manage `Chain`s.
 */
struct Table {
  Name name;
  Comment comment;
  struct list_head list;
  Chain *chain_head;
};

/**
 * Manage `Rule`s.
 */
struct Chain {
  Name name;
  ChainType type;
  enum nf_inet_hooks hook;
  ChainPriority priority;
  ChainPolicy policy;
  Comment comment;
  struct list_head list;
  Rule *rule_head;
  void *chain;
  void (*instantiate)(Chain *self, Argument *, ReturnT *);
};

/**
 * Manage `Match`es and `Stmt`s.
 */
struct Rule {
  Handle handle;
  Comment comment;
  struct list_head list;
  Match *match_head;
  Stmt *stmt_head;
};

/**
 * Compare `Packet` info and requirements.
 */
struct Match {
  MatchType type;
  struct list_head list;
  void *match;
  MatchResult (*instantiate)(Match *self, Argument *);
};

/**
 * The action performed when `Packet` gets through `Match`.
 */
struct Stmt {
  StmtType type;
  struct list_head list;
  void *stmt;
  void (*instantiate)(Stmt *self, Argument *, ReturnT *);
};


// Second level `Chain`s.

/**
 * Filter `Packet`
 */
struct FilterChain {
  // TODO: filter
};

// Second level `Stmt`s.

/**
 * The verdict statement alters control flow in the ruleset and issues policy decisions for `Packet`
 */
struct VerdictStmt {
  VerdictStmtType type;
  Name name_for_jump_or_goto;
  void (*instantiate)(VerdictStmt *self, Argument *, ReturnT *);
};


void chain_instantiate(Chain *self, Argument *, ReturnT *);
void stmt_instantiate(Stmt *self, Argument *, ReturnT *);

void verdict_instantiate(VerdictStmt *self, Argument *, ReturnT *);

#endif /*_FIREWALL_RULE_H*/ 
