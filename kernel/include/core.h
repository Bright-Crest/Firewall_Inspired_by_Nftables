/**
 * @file core.h
 * @author Bright-Crest (stephenzhu2004@163.com)
 * @brief The core and hierarchy of rule management.
 * @date 2024/07
 */

#ifndef _FIREWALL_RULE_H
#define _FIREWALL_RULE_H

#include "share.h"
#include "common.h"

#include <linux/stddef.h>     // used for `NULL`
#include <linux/netfilter.h>  // used for `enum nf_inet_hooks` 
#include <linux/list.h>       // for doubly linked list
#include <linux/list_sort.h>  // to sort `Chain`s by priority
#include <linux/string.h>     // used for `strncpy()`
#include <linux/slab.h>       // used for `kmalloc()` and `kfree()`
#include <linux/spinlock.h>   // use spin lock to assist RCU
// using rcu instead of read-write lock to mainly improve performance. Used for 
// rcu_read_lock(), rcu_read_unlock(), synchronize_rcu(), etc. Read-copy update 
// (RCU)  is a synchronization mechanism. RCU supports concurrency between a 
// single updater and multiple readers.
#include <linux/rcupdate.h> 


#define KMALLOC_KERNEL(_type, _name) _type *_name = (_type *)kmalloc(sizeof(_type), GFP_KERNEL)

/**
 * @brief Find an entry in a doubly linked list according to one key in the struct.
 * @details To support polymorphism. This can be applied to different structs with 
 *          `struct list_head` and searching according to different keys. Since this
 *          uses RCU and is the read-side, do not use this macro inside any locks.
 * @param _type type of the struct
 * @param _key_name name of the key within the struct
 * @param _key value of the key of the entry to find
 * @param _head `struct list_head`. The head of the list
 * @param _list_name name of `struct list_head` within the struct
 * @param _compare `int (*_compare)(KeyType key1, KeyType key2)`. The pointer to 
 *                 the function to compare keys. Return 0 if equal.
 * @return pointer to the first entry found. If not found, return NULL.
 */
#define LIST_FIND_RCU(_type, _key_name, _key, _head, _list_name, _compare) \
  ({\
    _type * _pos = NULL;\
    _type * _ret = NULL;\
    rcu_read_lock();\
    list_for_each_entry_rcu(_pos, &_head, _list_name) {\
      if (_compare(_pos->_key_name, _key) == 0) {\
        _ret = _pos;\
        break;\
      }\
    }\
    rcu_read_unlock();\
    _ret;\
  })

/** 
 * @brief Match value in an interval or match value not in an interval.
 * @details To support polymorphism like template. 
 *          When min_value > max_value, it means all the values.
 * @return 1: MATCH, 0: NOT_MATCH
 */
#define MATCH_INTERVAL(value, min_value, max_value, is_exclude) ({\
                                                                  typeof (value) _value = (value);\
                                                                  typeof (min_value) _min = (min_value);\
                                                                  typeof (max_value) _max = (max_value);\
                                                                  typeof (is_exclude) _is_exclude = (is_exclude);\
                                                                  int _result = 0;\
                                                                  if (_min <= _value && _value <= _max) {\
                                                                    _result = 1;\
                                                                  } else if (_min > _max) {\
                                                                    _result = 1;\
                                                                  } else {\
                                                                    _result = 0;\
                                                                  }\
                                                                  if (_is_exclude) {\
                                                                    _result = (_result + 1) % 2;\
                                                                  }\
                                                                  _result;\
                                                                })


// pre-definitions
struct Table;
struct Chain;
struct Rule;
struct Match;
struct Stmt;

struct FilterChain;

struct IPMatch;

struct VerdictStmt;


// make it simpler
typedef struct Table Table;
typedef struct Chain Chain;
typedef struct Rule Rule;
typedef struct Match Match;
typedef struct Stmt Stmt;

typedef struct FilterChain FilterChain;

typedef struct IPMatch IPMatch;

typedef struct VerdictStmt VerdictStmt;


// defined in core.c
extern struct list_head g_table_list_head;


// Top level structs.

/**
 * Manage `Chain`s.
 */
struct Table {
  Name name;
  Comment comment;
  struct list_head _list_node; ///< Internal list node to support being used in a list. Use the kernel in-built doubly linked list. 
  struct list_head chain_head; ///< External list head for maintain a list of `Chain`s.
};

/**
 * Manage `Rule`s.
 */
struct Chain {
  Name name;
  ChainType type;
  enum nf_inet_hooks hook;
  ChainPriority priority;
  Comment comment;
  struct list_head _list_node;
  struct list_head rule_head;
  void *chain;
  void (*instantiate)(Chain *self, Argument *, ReturnT *);
};

/**
 * Manage `Match`es and `Stmt`s.
 */
struct Rule {
  Handle handle; ///< Used to identify `Rule` which means this is unique in one `Chain`.
  Comment comment;
  struct list_head _list_node;
  struct list_head match_head;
  struct list_head stmt_head;
  void (*instantiate)(Rule *self, Argument *, ReturnT *);
};

/**
 * Compare `Packet` info and requirements.
 */
struct Match {
  MatchType type;
  struct list_head _list_node;
  void *match;
  MatchResult (*instantiate)(Match *self, Argument *);
};

/**
 * The action performed when `Packet` gets through `Match`.
 */
struct Stmt {
  StmtType type;
  struct list_head _list_node;
  void *stmt;
  void (*instantiate)(Stmt *self, Argument *, ReturnT *);
};


// Second level `Chain`s.

/**
 * Filter `Packet`
 */
struct FilterChain {
  ChainPolicy policy;
  void (*instantiate)(FilterChain *self, Argument *, ReturnT *);
};

// Second level `Match`es

/**
 * To match IP header
 */
struct IPMatch {
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
  MatchResult (*instantiate)(IPMatch *self, Argument *);
};

// Second level `Stmt`s.

/**
 * The verdict statement alters control flow in the ruleset and issues policy decisions for `Packet`.
 * 
 * Each `Rule` only contains one `VerdictStmt`.
 */
struct VerdictStmt {
  VerdictStmtType type;
  Name name_for_jump_or_goto;
  void (*instantiate)(VerdictStmt *self, Argument *, ReturnT *);
};


// function instantiation

void chain_instantiate(Chain *self, Argument *, ReturnT *);
void rule_instantiate(Rule *self, Argument *, ReturnT *);
MatchResult match_instantiate(Match *self, Argument *);
void stmt_instantiate(Stmt *self, Argument *, ReturnT *);

void filter_chain_instantiate(FilterChain *self, Argument *, ReturnT *);

MatchResult ip_match_instantiate(IPMatch *self, Argument *);

void verdict_stmt_instantiate(VerdictStmt *self, Argument *, ReturnT *);


// kmalloc struct, copy from structT and initialize additional members. Mainly used to communicate with user space.

Table * copy_table(TableT *_table);
Chain * copy_chain(ChainT *_chain);
Rule * copy_rule(RuleT *_rule);
Match * copy_match(MatchT *_match);
Stmt * copy_stmt(StmtT *_stmt);

FilterChain * copy_filter_chain(FilterChainT *_filter);

IPMatch * copy_ip_match(IPMatchT *_ipm);

VerdictStmt * copy_verdict_stmt(VerdictStmtT *_verdict);


// find 


// operations

void manage_table(TableT *_table, TableChangeType operation);
void manage_chain(ChainT *_chain, ChainChangeType operation, Name table_name);
void manage_rule(RuleT *_rule, RuleChangeType operation, Name table_name, Name chain_name);

// add
// void add_table(TableT *_table, );
// void add_chain();
// void add_rule();
// void add_match();
// void add_stmt(StmtT _stmt, struct list_head *prev);

// void add_filter_chain();

// void add_ip_match();

// void add_verdict_stmt(VerdictStmtT _verdict_stmt, );


#endif /*_FIREWALL_RULE_H*/ 
