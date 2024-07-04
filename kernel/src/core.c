#include "core.h"

#include "common.h"

#include <linux/string.h>
// for test
// #include <string.h>

/**
 * Used to initialize `Chain`.
 */
void chain_instantiate(Chain *self, Argument *argument, ReturnT *ret)
{
  switch (self->type)
  {
  case CHAIN_FILTER:
    FilterChain *filter = (FilterChain *)self->chain;
    // TODO: filter
    break;
  case CHAIN_NAT:
    break; 
  default:
    break;
  }
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

/**
 * Used to initialize `VerdictStmt`.
 */
void verdict_instantiate(VerdictStmt *self, Argument *argument, ReturnT *ret)
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
