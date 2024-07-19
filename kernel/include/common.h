#ifndef _FIREWALL_COMMON_H
#define _FIREWALL_COMMON_H

#include "share.h"

/**
 * Log level.
 */
#ifndef FIREWALL_INFO
#define FIREWALL_INFO 1
#endif
#ifndef FIREWALL_DEBUG
#define FIREWALL_DEBUG 1
#endif
#ifndef FIREWALL_WARN
#define FIREWALL_WARN 1
#endif
#ifndef FIREWALL_ERR
#define FIREWALL_ERR 1
#endif

#define PRINTK_INFO(fmt, args...)    do{\
                                       if (FIREWALL_INFO) {\
                                         printk("[FIREWALL_INFO] "fmt, ##args);\
                                       }\
                                     }while(0)
#define PRINTK_DEBUG(fmt, args...)    do{\
                                       if (FIREWALL_DEBUG) {\
                                         printk("[FIREWALL_DEBUG] %s: %d: "fmt, ##args);\
                                       }\
                                     }while(0)
#define PRINTK_WARN(fmt, args...)    do{\
                                       if (FIREWALL_WARN) {\
                                         printk("[FIREWALL_WARN] %s: %d: "fmt, ##args);\
                                       }\
                                     }while(0)
#define PRINTK_ERR(fmt, args...)    do{\
                                       if (FIREWALL_ERR) {\
                                         printk("[FIREWALL_ERR] %s: %d: "fmt, ##args);\
                                       }\
                                     }while(0)

/** 
 * @brief Match value in an interval or match value not in an interval.
 * @details To support polymorphyism like template. 
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
                                                                  if (is_exclude) {\
                                                                    _result = (_result + 1) % 2;\
                                                                  }\
                                                                  _result;\
                                                                })


typedef enum {PACKET_UNDECIDED, PACKET_ACCEPT, PACKET_DROP} PacketState;
typedef struct {
  unsigned int protocol; 
  unsigned int length;
  unsigned int saddr;
  unsigned int daddr;
  PacketState state;
} Packet;

typedef struct {
  Packet *packet;
} Argument;

typedef enum {OP_NONE, OP_RETURN, OP_JUMP, OP_GOTO} Operation;
typedef struct {
  PacketState state;
  Operation op;
  Name name;
} ReturnT;

#endif /*_FIREWALL_COMMON_H*/