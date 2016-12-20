MODULE_NAME := mfs_kthread
RESMAN_CORE_OBJS := fs_kthread.o
RESMAN_GLUE_OBJS := my_msg.o
$(MODULE_NAME)-objs := $(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
obj-m := mfs_kthread.o
all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(shell pwd) modules
clean:
	rm *.ko *.mod.* *.o *.order *.symvers
