#ifndef _FIREWALL_USER_COMM_H
#define _FIREWALL_USER_COMM_H


#include "api.h"

struct KernelResp ComWithKernel(void *smsg, unsigned int slen);

#endif /*_FIREWALL_USER_COMM_H*/