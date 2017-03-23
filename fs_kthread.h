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
#include <linux/time.h>
#include <linux/string.h>

//#include <linux/my_msg.h>
#include <linux/msgA_Sync.h>
#include <linux/interactive_design.h>
// #include "my_msg.h"


MODULE_LICENSE("GPL");

#define TEXT_SIZE 512
#define SEND_TIME 100000
#define PATH_SIZE 128

#define typeof __typeof__

#define Pointer(T) typeof(T *)
#define Array(T, N) typeof(T [N])
/*

#define Argus_msg0()                             \
    struct Argus_container0 {                    \
    }

#define Argus_msg1(type1)                        \
    struct Argus_container1 {                    \
      type1 argu1;                               \
    }

#define Argus_msg2(type1, type2)                 \
    struct Argus_container2 {                    \
      type1 argu1;                               \
      type2 argu2;                               \
    }

#define Argus_msg3(type1, type2, type3)            \
    struct Argus_container3 {                      \
      type1 argu1;                                 \
      type2 argu2;                                 \
      type3 argu3;                                 \
    }

#define Argus_msg4(type1, type2, type3, type4)           \
    struct Argus_container4 {                            \
      type1 argu1;                                       \
      type2 argu2;                                       \
      type3 argu3;                                       \
      type4 argu4;                                       \
    }

#define Argus_msg5(type1, type2, type3, type4, type5)            \
    struct Argus_container5 {                                    \
      type1 argu1;                                               \
      type2 argu2;                                               \
      type3 argu3;                                               \
      type4 argu4;                                               \
      type5 argu5;                                               \
    }

#define Argus_msg6(type1, type2, type3, type4, type5, type6)           \
    struct Argus_container6 {                                          \
      type1 argu1;                                                     \
      type2 argu2;                                                     \
      type3 argu3;                                                     \
      type4 argu4;                                                     \
      type5 argu5;                                                     \
      type6 argu6;                                                     \
    }

*/
static unsigned long long *syscall_table_addr;
int (*orig_write)(unsigned int fd,char *buf,unsigned int count);
int (*orig_open)(char *buf, int flags, umode_t mode);
int (*orig_read)(unsigned int fd, char *buf, unsigned int count);
int (*orig_close)(unsigned int fd);

// static int msqid_from_kernel_to_fs;
// static int msqid_from_fs_to_kernel;
extern bool fs_start;
extern struct task_struct *fs_temp;

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


// function declaration
static int getStrlength(char *buf);
int stoi(char *s);
void itos(int n, char *s);
static void get_syscall_table(void);
int hacked_write(unsigned int fd,char *buf,unsigned int count);
void deal_open_msg_ahead(struct my_msgbuf *this, void **retpp);
int hacked_open(char *buf, int flags, umode_t mode);
int hacked_read(unsigned int fd, char *buf, unsigned int count);
int hacked_close(unsigned int fd);
void deal_open_msg_back(struct my_msgbuf *this, void **retpp);
int fs_kthread_function(void *data);


#endif
