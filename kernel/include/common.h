#ifndef _FIREWALL_COMMON_H
#define _FIREWALL_COMMON_H

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

#define PRINT_INFO(fmt, args...)    do{\
                                       if (FIREWALL_INFO) {\
                                         printk("[FIREWALL_INFO] "fmt, ##args);\
                                       }\
                                     }while(0)
#define PRINT_DEBUG(fmt, args...)    do{\
                                       if (FIREWALL_DEBUG) {\
                                         printk("[FIREWALL_DEBUG] %s: %d: "fmt, __FILE__, __LINE__, ##args);\
                                       }\
                                     }while(0)
#define PRINT_WARN(fmt, args...)    do{\
                                       if (FIREWALL_WARN) {\
                                         printk("[FIREWALL_WARN] %s: %d: "fmt, __FILE__, __LINE__, ##args);\
                                       }\
                                     }while(0)
#define PRINT_ERR(fmt, args...)    do{\
                                       if (FIREWALL_ERR) {\
                                         printk("[FIREWALL_ERR] %s: %d: "fmt, __FILE__, __LINE__, ##args);\
                                       }\
                                     }while(0)

#define MAX_NAME_LENGTH 30
#define MAX_COMMENT_LENGTH 100

typedef char Name[MAX_NAME_LENGTH];
typedef char Comment[MAX_COMMENT_LENGTH];

typedef enum {PACKET_UNDECIDED, PACKET_ACCEPT, PACKET_DROP} PacketState;
typedef struct {
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