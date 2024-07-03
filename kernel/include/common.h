#ifndef _FIREWALL_COMMON_H
#define _FIREWALL_COMMON_H

#ifndef FIREWALL_INFO
#define FIREWALL_INFO 1
#endif
#ifndef FIREWALL_DEBUG
#define FIREWALL_DEBUG 1
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
#define PRINT_ERR(fmt, args...)    do{\
                                       if (FIREWALL_ERR) {\
                                         printk("[FIREWALL_ERR] %s: %d: "fmt, __FILE__, __LINE__, ##args);\
                                       }\
                                     }while(0)

#define MAX_NAME_LENGTH 30
#define MAX_COMMENT_LENGTH 100

typedef char Name[MAX_NAME_LENGTH];
typedef char Comment[MAX_COMMENT_LENGTH];

typedef enum {PACKAGE_UNDECIDED, PACKAGE_ACCEPT, PACKAGE_DROP} PackageState;
typedef struct {
  PackageState state;
} Package;

typedef struct {
  Package *package;
} Argument;

typedef enum {OP_NONE, OP_RETURN, OP_JUMP, OP_GOTO} Operation;
typedef struct {
  PackageState state;
  Operation op;
  Name name;
} ReturnT;

#endif /*_FIREWALL_COMMON_H*/