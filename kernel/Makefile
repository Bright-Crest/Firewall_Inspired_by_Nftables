MODULE_NAME = NftFirewall

# current kernel is built using gcc-12
CC=gcc-12

# relative path
SRC := src/core.c src/FT_Rules.c src/hook_func.c src/kernel_comm.c src/kernel_main.c

# absolute path
KERNEL_INCLUDE := $(src)/include
SHARE_INCLUDE := $(src)/../share/include

EXTRA_CFLAGS := -I$(KERNEL_INCLUDE) -I$(SHARE_INCLUDE)

ifneq ($(KERNELRELEASE),)
# kbuild part
obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-y := $(SRC:.c=.o)
ccflags-y := -I$(KERNEL_INCLUDE) -I$(SHARE_INCLUDE)

else
# normal makefile
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	insmod $(PWD)/$(MODULE_NAME).ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
# $(RM) -rf .*.cmd *.mod.c *.o *.ko .tmp* *.symvers *.order

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

endif