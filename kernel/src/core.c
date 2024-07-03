/*rule management*/
#include "core.h"

#include "common.h"

#include <linux/string.h>
// for test
// #include <string.h>

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

void verdict_instantiate(VerdictStmt *self, Argument *argument, ReturnT *ret)
{
  switch (self->type)
  {
  case VERDICT_ACCEPT:
    argument->package->state = PACKAGE_ACCEPT;
    ret->state = PACKAGE_ACCEPT;
    break;
  case VERDICT_DROP:
    argument->package->state = PACKAGE_DROP;
    ret->state = PACKAGE_DROP;
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
