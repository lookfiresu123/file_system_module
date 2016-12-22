#ifndef _HOOK_H
#define _HOOK_H 1

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/kthread.h>
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fcntl.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/resource.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <uapi/linux/limits.h>
#include <linux/compiler.h>
#include <linux/fsnotify.h>

// #include "hook.h"
#include "my_msg.h"
#include "open.h"

// MODULE_LICENSE("GPL");

#define EMBEDDED_NAME_MAX (PATH_MAX - sizeof(struct filename))

typedef unsigned long long ullong_type;

#define TEXT_SIZE 512
#define NAME_SIZE 32
#define MAX_INT ((1 << 31) - 1)
#define MIN_INT (-(1 << 31))
#define MAX_NUMS_SYSCALL_ARGC 6
//#define ULLONG_MAX (~(ullong_type)0)
//#define ADDR (*(volatile long *)addr)

static unsigned long long *syscall_table_addr;
static int (*orig_write)(unsigned int fd,char *buf,unsigned int count);
static int (*orig_open)(char *buf, int flags, umode_t mode);
static int (*orig_read)(unsigned int fd, char *buf, unsigned int count);
static int (*orig_close)(unsigned int fd);

static int msqid = -1;
static int isRemove_module = 0;
static int (*msgget)(key_t key, int msgflg);
static struct task_struct *tsk;
static long(*msgsnd)(int msqid, const void *msgp, size_t msgsz, int msgflg);
static ssize_t (*msgrcv)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
static int (*msgctl)(int msqid, int cmd, struct msqid_ds *buf);

// static inline void __set_bit(long nr, volatile unsigned long *addr) {
// 	asm volatile("bts %1, %0" : (*(volatile long *)addr) : "lr"(nr) : "memory");
// }

// static inline void __clear_bit(long nr, volatile unsigned long *addr) {
// 	asm volatile("bts %1, %0" : (*(volatile long *)addr) : "lr"(nr) : "memory");
// }


#endif
