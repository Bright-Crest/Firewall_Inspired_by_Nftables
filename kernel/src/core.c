#include "core.h"

// global variables

// static or not? No. Because it is used in hook functions
/**
 * The head of the table list. Its type is `struct list_head`.
 */
LIST_HEAD(g_table_list_head);
/**
 * Spin lock used to avoid updating concurrently.
 * 
 * Only used in this file, so `static`. There is only one lock in this file, 
 * so it applies to all the struct updaters. This is used along with RCU. 
 */
static DEFINE_SPINLOCK(_g_core_lock);
/**
 * Maintain a list of `Chain`s ordered by priority for each hook point
 */
LIST_HEAD(g_)

/**
 * Used to initialize `Chain`.
 */
void chain_instantiate(Chain *self, Argument *argument, ReturnT *ret)
{
  switch (self->type)
  {
  case CHAIN_FILTER:
    FilterChain *filter = (FilterChain *)self->chain;
    filter->instantiate(filter, argument, ret);
    // go through all the `Rule`s in order
    Rule *rule = NULL;
    rcu_read_lock();
    // remember to pass the pointer to the list head
    list_for_each_entry_rcu(rule, &self->rule_head, _list_node) {
      rule->instantiate(rule, argument, ret);
      // drop is done immediately
      if (ret->state == PACKET_DROP) {
        rcu_read_unlock();
        return;
      }
      // return, jump or goto is done immediately
      if (ret->op != OP_NONE) {
        rcu_read_unlock();
        return;
      }
    }
    rcu_read_unlock();
    
    // `Packet`s must have a decided state after going through a `FilterChain`.
    if (ret->state == PACKET_UNDECIDED) {
      if (filter->policy == CHAIN_ACCEPT) {
        argument->packet->state = PACKET_ACCEPT;
        ret->state = PACKET_ACCEPT;
      }
      else if (filter->policy == CHAIN_DROP) {
        argument->packet->state = PACKET_DROP;
        ret->state = PACKET_DROP;
      }
    }
    break;
  case CHAIN_NAT:
    // TODO: case CHAIN_NAT
    break; 
  default:
    break;
  }
}

void rule_instantiate(Rule *self, Argument *argument, ReturnT *ret)
{
  // first pass all `Match`es
  Match *match = NULL;
  rcu_read_lock();
  list_for_each_entry_rcu(match, &self->match_head, _list_node) {
    if (match->instantiate(match, argument) == NOT_MATCH) {
      rcu_read_unlock();
      return;
    }
  }
  rcu_read_unlock();

  // then go through all `Stmt`s
  Stmt *stmt = NULL;
  rcu_read_lock();
  list_for_each_entry_rcu(stmt, &self->stmt_head, _list_node) {
    stmt->instantiate(stmt, argument, ret);
  }
  rcu_read_unlock();
}

MatchResult match_instantiate(Match *self, Argument *argument)
{
  MatchResult ret = NOT_MATCH;
  switch (self->type)
  {
  case MATCH_IP:
    IPMatch *ipm = (IPMatch *)self->match;
    ret = ipm->instantiate(ipm, argument);
    break;
  default:
    break;
  }

  return ret;
}

/**
 * Used to initialize `Stmt`.
 */
void stmt_instantiate(Stmt *self, Argument *argument, ReturnT *ret)
{
  switch (self->type)
  {
  case STMT_VERDICT:
    VerdictStmt *verdict = (VerdictStmt *)self->stmt;
    verdict->instantiate(verdict, argument, ret);
    break;
  case STMT_LOG:
    // TODO: case STMT_LOG
    break;
  case STMT_COUNTER:
    break;
  case STMT_NAT:
    break;
  case STMT_CONNTRACK:
    break;
  default:
    break;
  }
}

void filter_chain_instantiate(FilterChain *self, Argument *argument, ReturnT *ret)
{
  // whenever a `Packet` enters a `FilterChain`, change the `PacketState` to PACKET_UNDECIDED
  argument->packet->state = PACKET_UNDECIDED;
  ret->state = PACKET_UNDECIDED;
}

MatchResult ip_match_instantiate(IPMatch *self, Argument *argument)
{
  if ((self->protocol == -1 || self->protocol == argument->packet->protocol)
      && MATCH_INTERVAL(argument->packet->length, self->min_length, self->max_length, self->is_length_exclude)
      && MATCH_INTERVAL(argument->packet->saddr, self->min_saddr, self->max_saddr, self->is_saddr_exclude)
      && MATCH_INTERVAL(argument->packet->daddr, self->min_daddr, self->max_daddr, self->is_daddr_exclude)
      && MATCH_INTERVAL(argument->packet->sport, self->min_sport, self->max_sport, self->is_sport_exclude)
      && MATCH_INTERVAL(argument->packet->dport, self->min_dport, self->max_dport, self->is_dport_exclude)) {
    return MATCH;
  } else {
    return NOT_MATCH;
  }
}

/**
 * Used to initialize `VerdictStmt`.
 */
void verdict_stmt_instantiate(VerdictStmt *self, Argument *argument, ReturnT *ret)
{
  switch (self->type)
  {
  case VERDICT_ACCEPT:
    argument->packet->state = PACKET_ACCEPT;
    ret->state = PACKET_ACCEPT;
    break;
  case VERDICT_DROP:
    argument->packet->state = PACKET_DROP;
    ret->state = PACKET_DROP;
    break;
  case VERDICT_CONTINUE: // do nothing
    break;
  case VERDICT_RETURN:
    ret->op = OP_RETURN;
    break;
  case VERDICT_JUMP:
    ret->op = OP_JUMP;
    strncpy(ret->name, self->name_for_jump_or_goto, MAX_NAME_LENGTH);
    break;
  case VERDICT_GOTO:
    ret->op = OP_GOTO;
    strncpy(ret->name, self->name_for_jump_or_goto, MAX_NAME_LENGTH);
    break;
  default:
    break;
  }
}

Table *copy_table(TableT *_table)
{
  KMALLOC_KERNEL(Table, t);
  strncpy(t->name, _table->name, MAX_NAME_LENGTH);
  strncpy(t->comment, _table->comment, MAX_COMMENT_LENGTH);
  INIT_LIST_HEAD(&t->chain_head);
  return t;
}

Chain *copy_chain(ChainT *_chain)
{
  KMALLOC_KERNEL(Chain, c);
  strncpy(c->name, _chain->name, MAX_NAME_LENGTH);
  c->type = _chain->type;
  c->hook = (enum nf_inet_hooks)(_chain->hook);
  c->priority = _chain->priority;
  strncpy(c->comment, _chain->comment, MAX_COMMENT_LENGTH);
  INIT_LIST_HEAD(&c->rule_head);
  c->instantiate = chain_instantiate;

  switch (c->type)
  {
  case CHAIN_FILTER:
    c->chain = (void *)copy_filter_chain(&_chain->chain.filter);
    break;
  default:
    c->chain = NULL;
    break;
  }
  return c;
}

Rule *copy_rule(RuleT *_rule)
{
  KMALLOC_KERNEL(Rule, r);
  r->handle = _rule->handle;
  strncpy(r->comment, _rule->comment, MAX_COMMENT_LENGTH);
  r->instantiate = rule_instantiate;

  // init the list heads of `Match`es and `Stmt`s
  // remember to pass the pointer 
  INIT_LIST_HEAD(&r->match_head);
  INIT_LIST_HEAD(&r->stmt_head);

  // no need to use RCU or lock here because this doesn't modify the original rules
  for (int i = 0; i < MAX_MATCH; i++)
  {
    Match *match = copy_match(&_rule->matches[i]);
    // remember to pass the pointer 
    list_add_tail(&match->_list_node, &r->match_head);
  }
  for (int i = 0; i < MAX_STMT; i++)
  {
    Stmt *stmt = copy_stmt(&_rule->stmts[i]);
    list_add_tail(&stmt->_list_node, &r->stmt_head);
  }
  
  return r;
}

Match *copy_match(MatchT *_match)
{
  KMALLOC_KERNEL(Match, m);
  m->type = _match->type;
  m->instantiate = match_instantiate;
  
  switch (m->type)
  {
  case MATCH_IP:
    m->match = (void *)copy_ip_match(&_match->match.ipm);
    break;
  default:
    m->match = NULL;
    break;
  }
  return m;
}

Stmt *copy_stmt(StmtT *_stmt)
{
  KMALLOC_KERNEL(Stmt, s);
  s->type = _stmt->stmt;
  s->instantiate = stmt_instantiate;

  switch (s->type)
  {
  case STMT_VERDICT:
    s->stmt = (void *)copy_verdict_stmt(&_stmt->stmt.verdict);
    break;
  case STMT_LOG:
    // TODO: case STMT_LOG copy
    s->stmt = NULL;
    break;
  default:
    s->stmt = NULL;
    break;
  }
  return s;
}

FilterChain *copy_filter_chain(FilterChainT *_filter)
{
  KMALLOC_KERNEL(FilterChain, f);
  f->policy = _filter->policy;
  f->instantiate = filter_chain_instantiate;
  return f;
}

IPMatch *copy_ip_match(IPMatchT *_ipm)
{
  KMALLOC_KERNEL(IPMatch, i);
  i->protocol = _ipm->protocol;
  i->is_length_exclude = _ipm->is_length_exclude;
  i->min_length = _ipm->min_length;
  i->max_length = _ipm->max_length;
  i->is_saddr_exclude = _ipm->is_saddr_exclude;
  i->min_saddr = _ipm->min_saddr;
  i->max_saddr = _ipm->max_saddr;
  i->is_daddr_exclude = _ipm->is_daddr_exclude;
  i->min_daddr = _ipm->min_daddr;
  i->max_daddr = _ipm->max_daddr;
  i->is_sport_exclude = _ipm->is_sport_exclude;
  i->min_sport = _ipm->min_sport;
  i->max_sport = _ipm->max_sport;
  i->is_dport_exclude = _ipm->is_dport_exclude;
  i->min_dport = _ipm->min_dport;
  i->max_dport = _ipm->max_dport;
  i->instantiate = ip_match_instantiate;
  return i;
}

VerdictStmt *copy_verdict_stmt(VerdictStmtT *_verdict)
{
  KMALLOC_KERNEL(VerdictStmt, v);
  v->type = _verdict->type;
  v->name_for_jump_or_goto = _verdict->name_for_jump_or_goto;
  v->instantiate = verdict_stmt_instantiate;
  return v;
}

void manage_table(TableT *_table, TableChangeType operation)
{
  switch (operation)
  {
  case ADD:
    Table *table = copy_table(_table);
    // remember to pass the pointer 
    spin_lock(&_g_core_lock);
    list_add_tail_rcu(&table->_list_node, &g_table_list_head);
    spin_unlock(&_g_core_lock);
    synchronize_rcu();
    break;
  case DELETE:
    break;
  case DESTROY:
    break;
  case LIST:
    break;
  case FLUSH:
    break;
  default:
    break;
  }
}

void manage_chain(ChainT *_chain, ChainChangeType operation, Name table_name)
{
  switch (operation)
  {
  case ADD:
    Chain *chain = copy_chain(_chain);
    Table *table = LIST_FIND_RCU(Table, name, table_name, g_table_list_head, _list_node, strcmp);
    if (!table) { // create a table if not found
      TableT _table = { .name = table_name };
      manage_table(&_table, ADD);
      table = LIST_FIND_RCU(Table, name, table_name, g_table_list_head, _list_node, strcmp);
    }
    spin_lock(&_g_core_lock);
    list_add_tail_rcu(&chain->_list_node, &table->chain_head);
    spin_unlock(&_g_core_lock);
    synchronize_rcu();
    break;
  case DELETE:
    break;
  case DESTROY:
    break;
  case LIST:
    break;
  case FLUSH:
    break;
  case CREATE:
    break;
  case RENAME:
    break;
  default:
    break;
  }
}

void manage_rule(RuleT *_rule, RuleChangeType operation, Name table_name, Name chain_name)
{ 
  switch (operation)
  {
  case ADD:
    Rule *rule = copy_rule(_rule);
    Table *table = LIST_FIND_RCU(Table, name, table_name, g_table_list_head, _list_node, strcmp);
    if (!table) {
      // TODO: error handle
      return;
    }
    Chain *chain = LIST_FIND_RCU(Chain, name, chain_name, table->chain_head, _list_node, strcmp);
    if (!chain) {
      // TODO: error handle
      return;
    }
    spin_lock(&_g_core_lock);
    list_add_tail_rcu(&rule->_list_node, &chain->rule_head);
    spin_unlock(&_g_core_lock);
    synchronize_rcu();
    break;
  case DELETE:
    break;
  case DESTROY:
    break;
  case INSERT:
    break;
  case REPLACE:
    break;
  case RESET:
    break;
  default:
    break;
  }
}

// void add_stmt(StmtT _stmt, struct list_head *prev)
// {
//   Stmt *
// }
