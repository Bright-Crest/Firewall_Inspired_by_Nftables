/**
 * @file comm_protocol.h
 * @author Bright-Crest (stephenzhu2004@163.com)
 * @brief The communication protocol shared by both kernel and user
 * @date 2024/07
 */

#ifndef _FIREWALL_COMM_PROTOCOL_H
#define _FIREWALL_COMM_PROTOCOL_H

#include "share.h"

#define NETLINK_MYFW 17

typedef enum {MANAGE, LOG_EXPORT, USER_RESPONSE} UserMsgType;
typedef enum {TABLE, CHAIN, RULE} Hierarchy;
// user to kernel

// one uniform header
typedef struct {
  UserMsgType type;
} UserMsgHeader;

// body

typedef struct {
  Hierarchy hierarchy;
  union {
    TableChangeType table_op;
    ChainChangeType chain_op;
    RuleChangeType rule_op;
  } operation;
  union {
    TableT table;
    ChainT chain;
    RuleT rule;
  } data;
  Name table_name; // used when hierarchy != TABLE
  Name chain_name; // used when hierarchy == RULE
} Manage;

typedef struct {
  // TODO: Add possible configurations (optional)
} LogExport;

/**
 * Used when user receives a log message and used to make kernel send the next
 * log message.
 * 
 * This should be used in a loop after sending `LogExport` because kernel will 
 * not send the next log message if kernel does not receive `UserResponse`.
 */
typedef struct {
} UserResponse;


// kernel to user
// header & body
typedef struct {
  // UserMsgType type;

} KernelResponse;

#endif /*_FIREWALL_COMM_PROTOCOL_H*/