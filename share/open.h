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
#include "ext4.h"
#include "ext4_jbd2.h"

#define IS_POSIX(fl)	(fl->fl_flags & FL_POSIX)
#define IS_FLOCK(fl)	(fl->fl_flags & FL_FLOCK)
#define IS_LEASE(fl)	(fl->fl_flags & (FL_LEASE|FL_DELEG))

extern struct files_stat_struct files_stat;
extern seqlock_t mount_lock;

/* ------------------------ ext4 文件系统的数据和结构 ----------------- */

static __cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_list_lock);
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_state_lock);
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_data_lock);
EXPORT_SYMBOL(dq_data_lock);

static LIST_HEAD(inuse_list);
static LIST_HEAD(free_dquots);
static unsigned int dq_hash_bits, dq_hash_mask;
static struct hlist_head *dquot_hash;


static inline unsigned int
hashfn(const struct super_block *sb, struct kqid qid)
{
	unsigned int id = from_kqid(&init_user_ns, qid);
	int type = qid.type;
	unsigned long tmp;

	tmp = (((unsigned long)sb>>L1_CACHE_SHIFT) ^ id) * (MAXQUOTAS - type);
	return (tmp + (tmp >> dq_hash_bits)) & dq_hash_mask;
}

static inline void insert_dquot_hash(struct dquot *dquot)
{
	struct hlist_head *head;
	head = dquot_hash + hashfn(dquot->dq_sb, dquot->dq_id);
	hlist_add_head(&dquot->dq_hash, head);
}

static inline void remove_free_dquot(struct dquot *dquot)
{
	if (list_empty(&dquot->dq_free))
		return;
	list_del_init(&dquot->dq_free);
	dqstats_dec(DQST_FREE_DQUOTS);
}

static void wait_on_dquot(struct dquot *dquot)
{
	mutex_lock(&dquot->dq_lock);
	mutex_unlock(&dquot->dq_lock);
}

static inline void do_destroy_dquot(struct dquot *dquot)
{
	dquot->dq_sb->dq_op->destroy_dquot(dquot);
}


static struct dquot *get_empty_dquot(struct super_block *sb, int type)
{
	struct dquot *dquot;

	dquot = sb->dq_op->alloc_dquot(sb, type);
	if(!dquot)
		return NULL;

	mutex_init(&dquot->dq_lock);
	INIT_LIST_HEAD(&dquot->dq_free);
	INIT_LIST_HEAD(&dquot->dq_inuse);
	INIT_HLIST_NODE(&dquot->dq_hash);
	INIT_LIST_HEAD(&dquot->dq_dirty);
	init_waitqueue_head(&dquot->dq_wait_unused);
	dquot->dq_sb = sb;
	dquot->dq_id = make_kqid_invalid(type);
	atomic_set(&dquot->dq_count, 1);

	return dquot;
}

static inline void put_inuse(struct dquot *dquot)
{
	/* We add to the back of inuse list so we don't have to restart
	 * when traversing this list and we block */
	list_add_tail(&dquot->dq_inuse, &inuse_list);
	dqstats_inc(DQST_ALLOC_DQUOTS);
}

static struct dquot *find_dquot(unsigned int hashent, struct super_block *sb,
                                struct kqid qid)
{
	struct hlist_node *node;
	struct dquot *dquot;

	hlist_for_each (node, dquot_hash+hashent) {
		dquot = hlist_entry(node, struct dquot, dq_hash);
		if (dquot->dq_sb == sb && qid_eq(dquot->dq_id, qid))
			return dquot;
	}
	return NULL;
}

static qsize_t *inode_reserved_space(struct inode * inode)
{
	/* Filesystem must explicitly define it's own method in order to use
	 * quota reservation interface */
	BUG_ON(!inode->i_sb->dq_op->get_reserved_space);
	return inode->i_sb->dq_op->get_reserved_space(inode);
}

static inline void dqput_all(struct dquot **dquot)
{
	unsigned int cnt;

	for (cnt = 0; cnt < MAXQUOTAS; cnt++)
		dqput(dquot[cnt]);
}

static inline void dquot_resv_space(struct dquot *dquot, qsize_t number)
{
	dquot->dq_dqb.dqb_rsvspace += number;
}

static qsize_t inode_get_rsv_space(struct inode *inode)
{
	qsize_t ret;

	if (!inode->i_sb->dq_op->get_reserved_space)
		return 0;
	spin_lock(&inode->i_lock);
	ret = *inode_reserved_space(inode);
	spin_unlock(&inode->i_lock);
	return ret;
}

static int dquot_active(const struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (IS_NOQUOTA(inode))
		return 0;
	return sb_any_quota_loaded(sb) & ~sb_any_quota_suspended(sb);
}


/*
 * Initialize quota pointers in inode
 *
 * We do things in a bit complicated way but by that we avoid calling
 * dqget() and thus filesystem callbacks under dqptr_sem.
 *
 * It is better to call this function outside of any transaction as it
 * might need a lot of space in journal for dquot structure allocation.
 */
static void __dquot_initialize(struct inode *inode, int type)
{
	int cnt;
	struct dquot *got[MAXQUOTAS] = {};
	struct super_block *sb = inode->i_sb;
	qsize_t rsv;

	/* First test before acquiring mutex - solves deadlocks when we
         * re-enter the quota code and are already holding the mutex */
	if (!dquot_active(inode))
		return;

	/* First get references to structures we might need. */
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		struct kqid qid;
		if (type != -1 && cnt != type)
			continue;
		switch (cnt) {
		case USRQUOTA:
			qid = make_kqid_uid(inode->i_uid);
			break;
		case GRPQUOTA:
			qid = make_kqid_gid(inode->i_gid);
			break;
		}
		got[cnt] = dqget(sb, qid);
	}

	down_write(&sb_dqopt(sb)->dqptr_sem);
	if (IS_NOQUOTA(inode))
		goto out_err;
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		if (type != -1 && cnt != type)
			continue;
		/* Avoid races with quotaoff() */
		if (!sb_has_quota_active(sb, cnt))
			continue;
		/* We could race with quotaon or dqget() could have failed */
		if (!got[cnt])
			continue;
		if (!inode->i_dquot[cnt]) {
			inode->i_dquot[cnt] = got[cnt];
			got[cnt] = NULL;
			/*
			 * Make quota reservation system happy if someone
			 * did a write before quota was turned on
			 */
			rsv = inode_get_rsv_space(inode);
			if (unlikely(rsv)) {
				spin_lock(&dq_data_lock);
				dquot_resv_space(inode->i_dquot[cnt], rsv);
				spin_unlock(&dq_data_lock);
			}
		}
	}
out_err:
	up_write(&sb_dqopt(sb)->dqptr_sem);
	/* Drop unused references */
	dqput_all(got);
}


void dquot_initialize(struct inode *inode)
{
	__dquot_initialize(inode, -1);
}


/*
 * Generic helper for ->open on filesystems supporting disk quotas.
 */
int dquot_file_open(struct inode *inode, struct file *file)
{
	int error;

	error = generic_file_open(inode, file);
	if (!error && (file->f_mode & FMODE_WRITE))
		dquot_initialize(inode);
	return error;
}

/*
 * Get reference to dquot
 *
 * Locking is slightly tricky here. We are guarded from parallel quotaoff()
 * destroying our dquot by:
 *   a) checking for quota flags under dq_list_lock and
 *   b) getting a reference to dquot before we release dq_list_lock
 */
struct dquot *dqget(struct super_block *sb, struct kqid qid)
{
	unsigned int hashent = hashfn(sb, qid);
	struct dquot *dquot = NULL, *empty = NULL;

        if (!sb_has_quota_active(sb, qid.type))
		return NULL;
we_slept:
	spin_lock(&dq_list_lock);
	spin_lock(&dq_state_lock);
	if (!sb_has_quota_active(sb, qid.type)) {
		spin_unlock(&dq_state_lock);
		spin_unlock(&dq_list_lock);
		goto out;
	}
	spin_unlock(&dq_state_lock);

	dquot = find_dquot(hashent, sb, qid);
	if (!dquot) {
		if (!empty) {
			spin_unlock(&dq_list_lock);
			empty = get_empty_dquot(sb, qid.type);
			if (!empty)
				schedule();	/* Try to wait for a moment... */
			goto we_slept;
		}
		dquot = empty;
		empty = NULL;
		dquot->dq_id = qid;
		/* all dquots go on the inuse_list */
		put_inuse(dquot);
		/* hash it first so it can be found */
		insert_dquot_hash(dquot);
		spin_unlock(&dq_list_lock);
		dqstats_inc(DQST_LOOKUPS);
	} else {
		if (!atomic_read(&dquot->dq_count))
			remove_free_dquot(dquot);
		atomic_inc(&dquot->dq_count);
		spin_unlock(&dq_list_lock);
		dqstats_inc(DQST_CACHE_HITS);
		dqstats_inc(DQST_LOOKUPS);
	}
	/* Wait for dq_lock - after this we know that either dquot_release() is
	 * already finished or it will be canceled due to dq_count > 1 test */
	wait_on_dquot(dquot);
	/* Read the dquot / allocate space in quota file */
	if (!test_bit(DQ_ACTIVE_B, &dquot->dq_flags) &&
	    sb->dq_op->acquire_dquot(dquot) < 0) {
		dqput(dquot);
		dquot = NULL;
		goto out;
	}
#ifdef CONFIG_QUOTA_DEBUG
	BUG_ON(!dquot->dq_sb);	/* Has somebody invalidated entry under us? */
#endif
out:
	if (empty)
		do_destroy_dquot(empty);

	return dquot;
}
EXPORT_SYMBOL(dqget);



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

#endif
