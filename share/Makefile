MODULE_NAME := hookfs
RESMAN_CORE_OBJS := hook.o
RESMAN_GLUE_OBJS := my_msg.o open.o

$(MODULE_NAME)-objs := $(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
obj-m := hookfs.o
all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(shell pwd) modules
clean:
	rm -rf *.ko *.mod.* *.o *.order *.symvers .tmp* .hook* .my* .open*
