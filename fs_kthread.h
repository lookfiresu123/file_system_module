#ifndef _FS_KTHREAD_H
#define _FS_KTHREAD_H 1

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
// #include <linux/msg.h>
#include <linux/kthread.h>
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/time.h>
#include "my_msg.h"

MODULE_LICENSE("GPL");

#define TEXT_SIZE 512
#define SEND_TIME 100000

#define typeof __typeof__

#define Pointer(T) typeof(T *)
#define Array(T, N) typeof(T [N])

#define Func_msg0(functype)                     \
    struct Func_container2 {                    \
        functype funcptr;                       \
    }

#define Func_msg1(functype, type1)              \
    struct Func_container2 {                    \
        functype funcptr;                       \
        type1 argu1;                            \
    }

#define Func_msg2(functype, type1, type2)       \
    struct Func_container2 {                    \
        functype funcptr;                       \
        type1 argu1;                            \
        type2 argu2;                            \
    }

#define Func_msg3(functype, type1, type2, type3)  \
    struct Func_container3 {                      \
        functype funcptr;                         \
        type1 argu1;                              \
        type2 argu2;                              \
        type3 argu3;                              \
    }

#define Func_msg4(functype, type1, type2, type3, type4) \
    struct Func_container4 {                            \
        functype funcptr;                               \
        type1 argu1;                                    \
        type2 argu2;                                    \
        type3 argu3;                                    \
        type4 argu4;                                    \
    }

#define Func_msg5(functype, type1, type2, type3, type4, type5)  \
    struct Func_container5 {                                    \
        functype funcptr;                                       \
        type1 argu1;                                            \
        type2 argu2;                                            \
        type3 argu3;                                            \
        type4 argu4;                                            \
        type5 argu5;                                            \
    }

#define Func_msg6(functype, type1, type2, type3, type4, type5, type6) \
    struct Func_container6 {                                          \
        functype funcptr;                                             \
        type1 argu1;                                                  \
        type2 argu2;                                                  \
        type3 argu3;                                                  \
        type4 argu4;                                                  \
        type5 argu5;                                                  \
        type6 argu6;                                                  \
    }

/*
struct my_msgbuf {
    long mtype;
    struct task_struct *tsk;
    void (*deal_data)(struct my_msgbuf *msgp, void **retpp);                 // 需要在初始化时注册处理函数，用于让接收方或发送方调用并处理该消息中的data_ptr
    union {
        void *func_container_ptr;
        void *object_ptr;
    } data;
};
*/

static unsigned long long *syscall_table_addr;
int (*orig_write)(unsigned int fd,char *buf,unsigned int count);
int (*orig_open)(char *buf, int flags, umode_t mode);
int (*orig_read)(unsigned int fd, char *buf, unsigned int count);
int (*orig_close)(unsigned int fd);

static int msqid_from_kernel_to_fs = -1;
static int msqid_from_fs_to_kernel = -1;
static int isRemove_module = 0;
struct work_struct current_work;    // 定义一个工作
struct timeval tpstart, tpend;
static struct task_struct *tsk = NULL;

/*
static int (*msgget)(key_t key, int msgflg);
static long(*msgsnd)(int msqid, const void *msgp, size_t msgsz, int msgflg);
static ssize_t (*msgrcv)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
static int (*msgctl)(int msqid, int cmd, struct msqid_ds *buf);
*/

#endif
