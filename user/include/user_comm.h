#ifndef _FIREWALL_USER_COMM_H
#define _FIREWALL_USER_COMM_H


#include "api.h"

struct KernelResp ComWithKernel(void *smsg, unsigned int slen);
void printFTRule(struct ftrule *rule);
void printNATRule(struct natrule *rule);
struct KernelResp addFtRule(struct ftrule *filter_rule, struct FTRule *k_filter_rule);
struct KernelResp getAllFTRules();
struct KernelResp delFTRule(char name[]);
struct KernelResp getLogs(char name[]);

#endif /*_FIREWALL_USER_COMM_H*/