// Test "core" and "common" modules in kernel.
// This also serves as an simple example and shows how to use a stmt.
// To compile, run 
// `gcc kernel/src/* test/kernel/core_test.c -Ikernel/include/ -g -o core_test`
// at the root directory and
// change the header file in kernel/core.c

#include "../../kernel/include/common.h"
#include "../../kernel/include/core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // for malloc

int main() {
  Package package = {
    .state = PACKAGE_UNDECIDED
  };

  Argument argument = {
    .package = &package
  };

  ReturnT ret = {
    .state = PACKAGE_UNDECIDED,
    .op = OP_NONE,
    .name = "\0"
  };

  VerdictStmt *verdict = malloc(sizeof(*verdict));
  verdict->type = VERDICT_ACCEPT;
  strcpy(verdict->name_for_jump_or_goto, "\0");
  verdict->instantiate = verdict_instantiate;

  Stmt *stmt = malloc(sizeof(*stmt));
  stmt->type = STMT_VERDICT;
  stmt->stmt = verdict;
  stmt->instantiate = stmt_instantiate;

  stmt->instantiate(stmt, &argument, &ret);

  if (package.state == PACKAGE_ACCEPT) {
    printf("PACKAGE_ACCEPT\n");
  }

  if (ret.state == PACKAGE_ACCEPT) {
    printf("ret accept\n");
  }
  
  return 0;
}