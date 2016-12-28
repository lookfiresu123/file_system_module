#ifndef _OPEN_H
#define _OPEN_H 1

// #include <linux/mount.h>
// #include <linux/seq_file.h>
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

#include "internal.h"
#include "log.h"
#include "ext4_open.h"
// #include "ext4.h"
// #include "ext4_jbd2.h"

#define IS_POSIX(fl)	(fl->fl_flags & FL_POSIX)
#define IS_FLOCK(fl)	(fl->fl_flags & FL_FLOCK)
#define IS_LEASE(fl)	(fl->fl_flags & (FL_LEASE|FL_DELEG))

#define EMBEDDED_NAME_MAX	(PATH_MAX - sizeof(struct filename))

extern struct files_stat_struct files_stat;
extern seqlock_t mount_lock;

/* ------------------ 虚拟文件系统的数据和函数 ---------------- */
struct mnt_namespace {
	atomic_t		count;
	unsigned int		proc_inum;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	int event;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	int m_count;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct rcu_head mnt_rcu;
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	struct path mnt_ex_mountpoint;
};

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;


/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the "rbr" RB tree.
 * Avoid increasing the size of this struct, there can be many thousands
 * of these on a server and we do not want this to take another cache line.
 */
struct epitem {
	union {
		/* RB tree node links this structure to the eventpoll RB tree */
		struct rb_node rbn;
		/* Used to free the struct epitem */
		struct rcu_head rcu;
	};

	/* List header used to link this structure to the eventpoll ready list */
	struct list_head rdllink;

	/*
	 * Works together "struct eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	struct epitem *next;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/* Number of active wait queue attached to poll operations */
	int nwait;

	/* List containing poll wait queues */
	struct list_head pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink;

	/* wakeup_source used when EPOLLWAKEUP is set */
	struct wakeup_source __rcu *ws;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};


struct eventpoll {
	/* Protect the access to this structure */
	spinlock_t lock;

	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* RB tree root used to store monitored fd structs */
	struct rb_root rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	/* wakeup_source used when ep_scan_ready_list is running */
	struct wakeup_source *ws;

	/* The user that created the eventpoll descriptor */
	struct user_struct *user;

	struct file *file;

	/* used to optimize loop detection check */
	int visited;
	struct list_head visited_list_link;
};

struct ima_digest_data {
	u8 algo;
	u8 length;
	union {
		struct {
			u8 unused;
			u8 type;
		} sha1;
		struct {
			u8 type;
			u8 algo;
		} ng;
		u8 data[2];
	} xattr;
	u8 digest[0];
} __packed;


/* integrity data associated with an inode */
struct integrity_iint_cache {
	struct rb_node rb_node;	/* rooted in integrity_iint_tree */
	struct inode *inode;	/* back pointer to inode in question */
	u64 version;		/* track inode changes */
	unsigned long flags;
	enum integrity_status ima_file_status:4;
	enum integrity_status ima_mmap_status:4;
	enum integrity_status ima_bprm_status:4;
	enum integrity_status ima_module_status:4;
	enum integrity_status evm_status:4;
	struct ima_digest_data *ima_hash;
};


#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt){
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt){
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt){
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);
extern struct mount *__lookup_mnt_last(struct vfsmount *, struct dentry *);

extern bool legitimize_mnt(struct vfsmount *, unsigned);

static inline void get_mnt_ns(struct mnt_namespace *ns){
	atomic_inc(&ns->count);
}

/*
static inline bool d_is_directory(const struct dentry *dentry) {
  return dentry->d_flags & DCACHE_ENTRY_TYPE;
}
*/


static inline void lock_mount_hash(void){
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void){
	write_sequnlock(&mount_lock);
}

struct proc_mounts {
	struct seq_file m;
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

#define proc_mounts(p) (container_of((p), struct proc_mounts, m))

extern const struct seq_operations mounts_op;


extern void my_files_init(void);
// extern int my_vfs_open(const struct path*, struct file *, const struct cred *);

extern struct file *my_do_filp_open(int , struct filename *, const struct open_flags *, struct task_struct *);

int my_open(const char *filename, int flags, umode_t mode, struct task_struct *get_current);

#endif
