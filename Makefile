obj-m := fs_kthread.o

all:
	make -C /home/lookfiresu/Desktop/linux-3.10.104 M=$(shell pwd) modules

clean:
	rm *.ko *.o *.symvers *.order *.mod.c

