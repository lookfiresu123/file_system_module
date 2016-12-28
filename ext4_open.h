#ifndef _EXT4_OPEN_H
#define _EXT4_OPEN_H

#include <linux/poll.h>
// #include <linux/fs.h>
// #include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/integrity.h>
// #include <linux/lglock.h>
#include <uapi/linux/eventpoll.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/hashtable.h>
#include <linux/ima.h>
#include <uapi/asm-generic/errno.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/percpu_counter.h>
#include <linux/preempt_mask.h>
#include <uapi/linux/capability.h>
#include <uapi/linux/fs.h>
#include <linux/lockref.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/list_bl.h>
#include <linux/lglock.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/audit.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/export.h>
#include <linux/tracepoint.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/rwsem.h>
#include <linux/task_work.h>
#include <linux/pid_namespace.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/user_namespace.h>
#include <asm/uaccess.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>
#include <linux/eventpoll.h>
#include <linux/dcache.h>
#include <uapi/linux/stat.h>
#include <linux/uidgid.h>
#include <linux/posix_acl.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/jbd2.h>
#include <linux/quotaops.h>

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/kmod.h>
#include <linux/namei.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
// #include <trace/events/ext4.h>
#include <linux/vermagic.h>

// #include "internal.h"
#include "log.h"
#include "ext4.h"
#include "ext4_jbd2.h"
#include <trace/events/ext4.h>

/*
 * Journal flag definitions
 */
#define JBD2_UNMOUNT	0x001	/* Journal thread is being destroyed */
#define JBD2_ABORT	0x002	/* Journaling has been aborted for errors. */
#define JBD2_ACK_ERR	0x004	/* The errno in the sb has been acked */
#define JBD2_FLUSHED	0x008	/* The journal superblock has been flushed */
#define JBD2_LOADED	0x010	/* The journal superblock has been loaded */
#define JBD2_BARRIER	0x020	/* Use IDE barriers */
#define JBD2_ABORT_ON_SYNCDATA_ERR	0x040	/* Abort the journal on file
                                           * data write error in ordered
                                           * mode */
#define JBD2_REC_ERR	0x080	/* The errno in the sb has been recorded */

#define ext4_error_ratelimit(sb)                      \
  ___ratelimit(&(EXT4_SB(sb)->s_err_ratelimit_state),	\
               "EXT4-fs error")


int my_ext4_file_open(struct inode * inode, struct file * filp, struct task_struct *t);

#endif
