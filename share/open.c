/*
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
*/

#include "open.h"
// #include "log.h"

#define IS_POSIX(fl)	(fl->fl_flags & FL_POSIX)
#define IS_FLOCK(fl)	(fl->fl_flags & FL_FLOCK)
#define IS_LEASE(fl)	(fl->fl_flags & (FL_LEASE|FL_DELEG))


struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

static struct kmem_cache *filp_cachep;
static struct percpu_counter nr_files;
static struct kmem_cache *filp_cachep __read_mostly;
static struct hlist_head *mount_hashtable __read_mostly;
static struct hlist_head *mountpoint_hashtable __read_mostly;
static struct kmem_cache *mnt_cache __read_mostly;
static unsigned int m_hash_mask __read_mostly;
static unsigned int m_hash_shift __read_mostly;
static unsigned int mp_hash_mask __read_mostly;
static unsigned int mp_hash_shift __read_mostly;
static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;
static struct hlist_bl_head *dentry_hashtable __read_mostly;

static DECLARE_RWSEM(namespace_sem);
DEFINE_STATIC_LGLOCK(file_lock_lglock);
static DEFINE_SPINLOCK(blocked_lock_lock);
static LLIST_HEAD(delayed_fput_list);
static DEFINE_MUTEX(epmutex);
DEFINE_SEQLOCK(mount_lock);

struct cred* my_current_cred(struct task_struct *t) {
	return rcu_dereference_protected(t->cred, 1);
}

kuid_t my_current_fsuid(struct task_struct *t)
{
	return my_current_cred(t)->fsuid;
}

void my_files_init(void)
{ 
	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	files_stat.max_files = NR_FILE;
	percpu_counter_init(&nr_files, 0);
} 

struct file* my_get_empty_filp(struct task_struct *t) {
	const struct cred *cred = my_current_cred(t);
	static long old_max;
	struct file *f;
	int error;

	my_files_init();
	/*
	 * Privileged users can go above max_files
	 */
  DEBUG_LOG("enter percpu_counter_read_positive!");
	if (percpu_counter_read_positive(&nr_files) >= files_stat.max_files) {
		/*
		 * percpu_counters are inaccurate.  Do an expensive check before
		 * we go and fail.
		 */
		if (percpu_counter_sum_positive(&nr_files) >= files_stat.max_files)
			goto over;
	}

	DEBUG_LOG("enter kmem_cache_zalloc!");
	f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
	if (unlikely(!f))
		return ERR_PTR(-ENOMEM);

	DEBUG_LOG("enter percpu_counter_inc!");
	percpu_counter_inc(&nr_files);
	f->f_cred = get_cred(cred);

	/*
	error = security_file_alloc(f);
	if (unlikely(error)) {
		file_free(f);
		return ERR_PTR(error);
	}
	*/
	DEBUG_LOG("enter atomic_long_set!");
	atomic_long_set(&f->f_count, 1);
	rwlock_init(&f->f_owner.lock);
	spin_lock_init(&f->f_lock);
	eventpoll_init_file(f);
	/* f->f_version: 0 */
	return f;

over:
	/* Ran out of filps - report that */
	if (percpu_counter_read_positive(&nr_files) > old_max) {
		printk(KERN_INFO "VFS: file-max limit %lu reached\n", files_stat.max_files);
		old_max = percpu_counter_read_positive(&nr_files);
	}
	return ERR_PTR(-ENFILE);
}

static int sb_permission(struct super_block *sb, struct inode *inode, int mask) {
	if(unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		/* Nobody gets write access to a read-only fs. */
		if ((sb->s_flags & MS_RDONLY) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}

int groups_search(const struct group_info *group_info, kgid_t grp)
{
	unsigned int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		unsigned int mid = (left+right)/2;
		if (gid_gt(grp, GROUP_AT(group_info, mid)))
			left = mid + 1;
		else if (gid_lt(grp, GROUP_AT(group_info, mid)))
			right = mid;
		else
			return 1;
	}
	return 0;
}


/*
 * Check whether we're fsgid/egid or in the supplemental group..
 */
int my_in_group_p(kgid_t grp, struct task_struct *t)
{
	const struct cred *cred = my_current_cred(t);
	int retval = 1;

	if (!gid_eq(grp, cred->fsgid))
		retval = groups_search(cred->group_info, grp);
	return retval;
}

int my_posix_acl_permission(struct inode *inode, const struct posix_acl *acl, int want, struct task_struct *t)
{
	const struct posix_acl_entry *pa, *pe, *mask_obj;
	int found = 0;

	want &= MAY_READ | MAY_WRITE | MAY_EXEC | MAY_NOT_BLOCK;

	FOREACH_ACL_ENTRY(pa, acl, pe) {
                switch(pa->e_tag) {
                        case ACL_USER_OBJ:
				if (uid_eq(inode->i_uid, my_current_fsuid(t)))
                                        goto check_perm;
                                break;
                        case ACL_USER:
				if (uid_eq(pa->e_uid, my_current_fsuid(t)))
                                        goto mask;
				break;
                        case ACL_GROUP_OBJ:
                                if (my_in_group_p(inode->i_gid, t)) {
					found = 1;
					if ((pa->e_perm & want) == want)
						goto mask;
                                }
				break;
                        case ACL_GROUP:
				if (my_in_group_p(pa->e_gid, t)) {
					found = 1;
					if ((pa->e_perm & want) == want)
						goto mask;
                                }
                                break;
                        case ACL_MASK:
                                break;
                        case ACL_OTHER:
				if (found)
					return -EACCES;
				else
					goto check_perm;
			default:
				return -EIO;
                }
        }
	return -EIO;

mask:
	for (mask_obj = pa+1; mask_obj != pe; mask_obj++) {
		if (mask_obj->e_tag == ACL_MASK) {
			if ((pa->e_perm & mask_obj->e_perm & want) == want)
				return 0;
			return -EACCES;
		}
	}

check_perm:
	if ((pa->e_perm & want) == want)
		return 0;
	return -EACCES;
}


static int my_check_acl(struct inode *inode, int mask, struct task_struct *t)
{
	struct posix_acl *acl;

	if (mask & MAY_NOT_BLOCK) {
		acl = get_cached_acl_rcu(inode, ACL_TYPE_ACCESS);
	        	if (!acl)
	           	return -EAGAIN;
		if (acl == ACL_NOT_CACHED)
			return -ECHILD;
	           return my_posix_acl_permission(inode, acl, mask & ~MAY_NOT_BLOCK, t);
	}

	acl = get_cached_acl(inode, ACL_TYPE_ACCESS);

	/*
	 * A filesystem can force a ACL callback by just never filling the
	 * ACL cache. But normally you'd fill the cache either at inode
	 * instantiation time, or on the first ->get_acl call.
	 *
	 * If the filesystem doesn't have a get_acl() function at all, we'll
	 * just create the negative cache entry.
	 */
	if (acl == ACL_NOT_CACHED) {
	        if (inode->i_op->get_acl) {
			acl = inode->i_op->get_acl(inode, ACL_TYPE_ACCESS);
			if (IS_ERR(acl))
				return PTR_ERR(acl);
		} else {
		        set_cached_acl(inode, ACL_TYPE_ACCESS, NULL);
		        return -EAGAIN;
		}
	}

	if (acl) {
	        int error = my_posix_acl_permission(inode, acl, mask, t);
	        posix_acl_release(acl);
	        return error;
	}
}


static int my_acl_permission_check(struct inode *inode, int mask, struct task_struct *t)
{
	unsigned int mode = inode->i_mode;

	if (likely(uid_eq(my_current_fsuid(t), inode->i_uid)))
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
			int error = my_check_acl(inode, mask, t);
			if (error != -EAGAIN)
				return error;
		}

		if (my_in_group_p(inode->i_gid, t))
			mode >>= 3;
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 */
	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

bool my_ns_capable(struct user_namespace *ns, int cap, struct task_struct *t)
{
	if (unlikely(!cap_valid(cap))) {
		printk(KERN_CRIT "capable() called with invalid cap=%u\n", cap);
		BUG();
	}
	/*
	if (security_capable(my_current_cred(t), ns, cap) == 0) {
		t->flags |= PF_SUPERPRIV;
		return true;
	}
	*/
	return true;
}


bool my_capable_wrt_inode_uidgid(const struct inode *inode, int cap, struct task_struct *t)
{
	struct user_namespace *ns = current_user_ns();

	return my_ns_capable(ns, cap, t) && kuid_has_mapping(ns, inode->i_uid) &&
		kgid_has_mapping(ns, inode->i_gid);
}

int my_generic_permission(struct inode *inode, int mask, struct task_struct *t)
{
	int ret;

	/*
	 * Do the basic permission checks.
	 */
	ret = my_acl_permission_check(inode, mask, t);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		/* DACs are overridable for directories */
		if (my_capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE, t))
			return 0;
		if (!(mask & MAY_WRITE))
			if (my_capable_wrt_inode_uidgid(inode,
						     CAP_DAC_READ_SEARCH, t))
				return 0;
		return -EACCES;
	}
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable when there is
	 * at least one exec bit set.
	 */
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (my_capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE, t))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
		if (my_capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH, t))
			return 0;

	return -EACCES;
}

static inline int my_do_inode_permission(struct inode *inode, int mask, struct task_struct *t)
{
	/*we didn't consider this condition
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	*/
	return my_generic_permission(inode, mask, t);
}


int __my_inode_permission(struct inode *inode, int mask, struct task_struct *t) {
	int retval;

	if (unlikely(mask & MAY_WRITE)) {
		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}

	retval = my_do_inode_permission(inode, mask, t);
	if (retval)
		return retval;

	/* we didn't consider devcgroup
	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;
	*/

	/* we didn't consider LSM
	return security_inode_permission(inode, mask);
	*/
}

int my_inode_permission(struct inode *inode, int mask, struct task_struct *t) {
	int retval;

	retval = sb_permission(inode->i_sb, inode, mask);
	if(retval)
		return retval;
	return __my_inode_permission(inode, mask, t);
}

static  unsigned my_set_root_rcu(struct nameidata *nd, struct task_struct *t)
{
	struct fs_struct *fs = t->fs;
	unsigned seq, res;

	do {
		seq = read_seqcount_begin(&fs->seq);
		nd->root = fs->root;
		res = __read_seqcount_begin(&nd->root.dentry->d_seq);
	} while (read_seqcount_retry(&fs->seq, seq));
	return res;
}

static  void my_set_root(struct nameidata *nd, struct task_struct *t)
{
	get_fs_root(t->fs, &nd->root);
}

struct file *my_fget_raw_light(unsigned int fd, int *fput_needed, struct task_struct *t)
{
	struct file *file;
	struct files_struct *files = t->files;

	*fput_needed = 0;
	if (atomic_read(&files->count) == 1) {
		file = fcheck_files(files, fd);
	} else {
		rcu_read_lock();
		file = fcheck_files(files, fd);
		if (file) {
			if (atomic_long_inc_not_zero(&file->f_count))
				*fput_needed = 1;
			else
				/* Didn't get the reference, someone's freed */
				file = NULL;
		}
		rcu_read_unlock();
	}

	return file;
}


static struct fd my_fdget_raw(unsigned int fd, struct task_struct *t)
{
	int b;
	struct file *f = my_fget_raw_light(fd, &b, t);
	return (struct fd){f,b};
}

static int path_init(int dfd, const char *name, unsigned int flags, struct nameidata *nd, struct file **fp, struct task_struct *t) {
	int retval = 0;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags | LOOKUP_JUMPED;
	nd->depth = 0;
	if (flags & LOOKUP_ROOT) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*name) {
			if (!d_is_directory(root))
				return -ENOTDIR;
			retval = my_inode_permission(inode, MAY_EXEC, t);
			if (retval)
				return retval;
		}
		printk(KERN_INFO "my_inode_permission exec! the result is %d\n", retval);
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			path_get(&nd->path);
		}
		return 0;
	}

	nd->root.mnt = NULL;

	nd->m_seq = read_seqbegin(&mount_lock);
	if (*name=='/') {
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			my_set_root_rcu(nd, t);
		} else {
			my_set_root(nd, t);
			path_get(&nd->root);
		}
		nd->path = nd->root;
	} else if (dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = t->fs;
			unsigned seq;

			rcu_read_lock();

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(t->fs, &nd->path);
		}
	} else {
		/* Caller must check execute permissions on the starting path component */
		struct fd f = my_fdget_raw(dfd, t);
		struct dentry *dentry;

		if (!f.file)
			return -EBADF;

		dentry = f.file->f_path.dentry;

		if (*name) {
			if (!d_is_directory(dentry)) {
				fdput(f);
				return -ENOTDIR;
			}
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			if (f.need_put)
				*fp = f.file;
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			rcu_read_lock();
		} else {
			path_get(&nd->path);
			fdput(f);
		}
	}

	nd->inode = nd->path.dentry->d_inode;
	return 0;
}

void mnt_add_count(struct mount *mnt, int n)
{
#ifdef CONFIG_SMP
	this_cpu_add(mnt->mnt_pcp->mnt_count, n);
#else
	preempt_disable();
	mnt->mnt_count += n;
	preempt_enable();
#endif
}

bool legitimize_mnt(struct vfsmount *bastard, unsigned seq)
{
	struct mount *mnt;
	if (read_seqretry(&mount_lock, seq))
		return false;
	if (bastard == NULL)
		return true;
	mnt = real_mount(bastard);
	mnt_add_count(mnt, 1);
	if (likely(!read_seqretry(&mount_lock, seq)))
		return true;
	if (bastard->mnt_flags & MNT_SYNC_UMOUNT) {
		mnt_add_count(mnt, -1);
		return false;
	}
	rcu_read_unlock();
	mntput(bastard);
	rcu_read_lock();
	return false;
}

static int my_unlazy_walk(struct nameidata *nd, struct dentry *dentry, struct task_struct *t)
{
	struct fs_struct *fs = t->fs;
	struct dentry *parent = nd->path.dentry;

	if (!legitimize_mnt(nd->path.mnt, nd->m_seq))
		return -ECHILD;
	nd->flags &= ~LOOKUP_RCU;

	if (!lockref_get_not_dead(&parent->d_lockref)) {
		nd->path.dentry = NULL;	
		goto out;
	}

	if (!dentry) {
		if (read_seqcount_retry(&parent->d_seq, nd->seq))
			goto out;
	} else {
		if (!lockref_get_not_dead(&dentry->d_lockref))
			goto out;
		if (read_seqcount_retry(&dentry->d_seq, nd->seq))
			goto drop_dentry;
	}

	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		spin_lock(&fs->lock);
		if (nd->root.mnt != fs->root.mnt || nd->root.dentry != fs->root.dentry)
			goto unlock_and_drop_dentry;
		path_get(&nd->root);
		spin_unlock(&fs->lock);
	}

	rcu_read_unlock();
	return 0;

unlock_and_drop_dentry:
	spin_unlock(&fs->lock);
drop_dentry:
	rcu_read_unlock();
	dput(dentry);
	goto drop_root_mnt;
out:
	rcu_read_unlock();
drop_root_mnt:
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	return -ECHILD;
}

static int my_may_lookup(struct nameidata *nd, struct task_struct *t)
{
	if (nd->flags & LOOKUP_RCU) {
		int err = my_inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK, t);
		if (err != -ECHILD)
			return err;
		if (my_unlazy_walk(nd, NULL, t))
			return -ECHILD;
	}
	return my_inode_permission(nd->inode, MAY_EXEC, t);
}

static unsigned long my_hash_name(const char *name, unsigned int *hashp)
{
	unsigned long hash = init_name_hash();
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	*hashp = end_name_hash(hash);
	return len;
}

DEFINE_SEQLOCK(rename_lock);

struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; !IS_ROOT(p); p = p->d_parent) {
		if (p->d_parent == p1)
			return p;
	}
	return NULL;
}


int is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
{
	int result;
	unsigned seq;

	if (new_dentry == old_dentry)
		return 1;

	do {
		/* for restarting inner loop in case of seq retry */
		seq = read_seqbegin(&rename_lock);
		/*
		 * Need rcu_readlock to protect against the d_parent trashing
		 * due to d_move
		 */
		rcu_read_lock();
		if (d_ancestor(old_dentry, new_dentry))
			result = 1;
		else
			result = 0;
		rcu_read_unlock();
	} while (read_seqretry(&rename_lock, seq));

	return result;
}


static bool path_connected(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;

	if (mnt->mnt_root == mnt->mnt_sb->s_root)
		return true;

	return is_subdir(path->dentry, mnt->mnt_root);
}

static int follow_up_rcu(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	parent = mnt->mnt_parent;
	if (&parent->mnt == path->mnt)
		return 0;
	mountpoint = mnt->mnt_mountpoint;
	path->dentry = mountpoint;
	path->mnt = &parent->mnt;
	return 1;
}

static int my_follow_dotdot_rcu(struct nameidata *nd, struct task_struct *t)
{
	struct inode *inode = nd->inode;
	if (!nd->root.mnt)
		my_set_root_rcu(nd, t);

	while (1) {
		if (nd->path.dentry == nd->root.dentry &&
		    nd->path.mnt == nd->root.mnt) {
			break;
		}
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			struct dentry *old = nd->path.dentry;
			struct dentry *parent = old->d_parent;
			unsigned seq;

			inode = parent->d_inode;
			seq = read_seqcount_begin(&parent->d_seq);
			if (read_seqcount_retry(&old->d_seq, nd->seq))
				goto failed;
			nd->path.dentry = parent;
			nd->seq = seq;
			if (unlikely(!path_connected(&nd->path)))
				goto failed;
			break;
		}
		if (!follow_up_rcu(&nd->path))
			break;
		inode = nd->path.dentry->d_inode;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
	/* we didn't consider the mount point
	while (d_mountpoint(nd->path.dentry)) {
		struct mount *mounted;
		mounted = __lookup_mnt(nd->path.mnt, nd->path.dentry);
		if (!mounted)
			break;
		nd->path.mnt = &mounted->mnt;
		nd->path.dentry = mounted->mnt.mnt_root;
		inode = nd->path.dentry->d_inode;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
		if (!read_seqretry(&mount_lock, nd->m_seq))
			goto failed;
	}
	*/
	nd->inode = inode;
	return 0;

failed:
	nd->flags &= ~LOOKUP_RCU;
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	rcu_read_unlock();
	return -ECHILD;
}

struct vfsmount *lookup_mnt(struct path *path)
{
	struct mount *child_mnt;
	struct vfsmount *m;
	unsigned seq;

	rcu_read_lock();
	do {
		seq = read_seqbegin(&mount_lock);
		child_mnt = __lookup_mnt(path->mnt, path->dentry);
		m = child_mnt ? &child_mnt->mnt : NULL;
	} while (!legitimize_mnt(m, seq));
	rcu_read_unlock();
	return m;
}


static void follow_mount(struct path *path)
{
	while (d_mountpoint(path->dentry)) {
		struct vfsmount *mounted = lookup_mnt(path);
		if (!mounted)
			break;
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
	}
}

static int my_follow_dotdot(struct nameidata *nd, struct task_struct *t)
{
	if (!nd->root.mnt)
		my_set_root(nd, t);

	while(1) {
		struct dentry *old = nd->path.dentry;

		if (nd->path.dentry == nd->root.dentry &&
		    nd->path.mnt == nd->root.mnt) {
			break;
		}
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			nd->path.dentry = dget_parent(nd->path.dentry);
			dput(old);
			if (unlikely(!path_connected(&nd->path))) {
				path_put(&nd->path);
				return -ENOENT;
			}
			break;
		}
		if (!follow_up(&nd->path))
			break;
	}
	follow_mount(&nd->path);
	nd->inode = nd->path.dentry->d_inode;
	return 0;
}


static int my_handle_dots(struct nameidata *nd, int type, struct task_struct *t)
{
	if (type == LAST_DOTDOT) {
		if (nd->flags & LOOKUP_RCU) {
			if (my_follow_dotdot_rcu(nd, t))
				return -ECHILD;
		} else
			return my_follow_dotdot(nd, t);
	}
	return 0;
}

static bool managed_dentry_might_block(struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_MANAGE_TRANSIT &&
		dentry->d_op->d_manage(dentry, true) < 0);
}

struct hlist_head *m_hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long)mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long)dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> m_hash_shift);
	return &mount_hashtable[tmp & m_hash_mask];
}


struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	struct hlist_head *head = m_hash(mnt, dentry);
	struct mount *p;

	hlist_for_each_entry_rcu(p, head, mnt_hash)
		if (&p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
			return p;
	return NULL;
}

static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
			       struct inode **inode)
{
	for (;;) {
		struct mount *mounted;
		if (unlikely(managed_dentry_might_block(path->dentry)))
			return false;

		if (!(path->dentry->d_flags & DCACHE_MOUNTED))
			return true;

		mounted = __lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		path->mnt = &mounted->mnt;
		path->dentry = mounted->mnt.mnt_root;
		nd->flags |= LOOKUP_JUMPED;
		nd->seq = read_seqcount_begin(&path->dentry->d_seq);
		*inode = path->dentry->d_inode;
	}
	return read_seqretry(&mount_lock, nd->m_seq);
}

/* we didn't consider auto mountpoint
static void namespace_lock(void)
{
	down_write(&namespace_sem);
}

static struct mountpoint *new_mountpoint(struct dentry *dentry)
{
	struct hlist_head *chain = mp_hash(dentry);
	struct mountpoint *mp;
	int ret;

	hlist_for_each_entry(mp, chain, m_hash) {
		if (mp->m_dentry == dentry) {
			if (d_unlinked(dentry))
				return ERR_PTR(-ENOENT);
			mp->m_count++;
			return mp;
		}
	}

	mp = kmalloc(sizeof(struct mountpoint), GFP_KERNEL);
	if (!mp)
		return ERR_PTR(-ENOMEM);

	ret = d_set_mounted(dentry);
	if (ret) {
		kfree(mp);
		return ERR_PTR(ret);
	}

	mp->m_dentry = dentry;
	mp->m_count = 1;
	hlist_add_head(&mp->m_hash, chain);
	return mp;
}

static struct mountpoint *lock_mount(struct path *path)
{
	struct vfsmount *mnt;
	struct dentry *dentry = path->dentry;
retry:
	mutex_lock(&dentry->d_inode->i_mutex);
	if (unlikely(cant_mount(dentry))) {
		mutex_unlock(&dentry->d_inode->i_mutex);
		return ERR_PTR(-ENOENT);
	}
	namespace_lock();
	mnt = lookup_mnt(path);
	if (likely(!mnt)) {
		struct mountpoint *mp = new_mountpoint(dentry);
		if (IS_ERR(mp)) {
			namespace_unlock();
			mutex_unlock(&dentry->d_inode->i_mutex);
			return mp;
		}
		return mp;
	}
	namespace_unlock();
	mutex_unlock(&path->dentry->d_inode->i_mutex);
	path_put(path);
	path->mnt = mnt;
	dentry = path->dentry = dget(mnt->mnt_root);
	goto retry;
}

static int do_add_mount(struct mount *newmnt, struct path *path, int mnt_flags, struct task_struct *t)
{
	struct mountpoint *mp;
	struct mount *parent;
	int err;

	mnt_flags &= ~MNT_INTERNAL_FLAGS;

	mp = lock_mount(path);
	if (IS_ERR(mp))
		return PTR_ERR(mp);

	parent = real_mount(path->mnt);
	err = -EINVAL;
	if (unlikely(!check_mnt(parent))) {
		if (!(mnt_flags & MNT_SHRINKABLE))
			goto unlock;
		if (!parent->mnt_ns)
			goto unlock;
	}

	err = -EBUSY;
	if (path->mnt->mnt_sb == newmnt->mnt.mnt_sb &&
	    path->mnt->mnt_root == path->dentry)
		goto unlock;

	err = -EINVAL;
	if (S_ISLNK(newmnt->mnt.mnt_root->d_inode->i_mode))
		goto unlock;

	newmnt->mnt.mnt_flags = mnt_flags;
	err = graft_tree(newmnt, parent, mp);

unlock:
	unlock_mount(mp);
	return err;
}

int finish_automount(struct vfsmount *m, struct path *path, struct task_struct *t)
{
	struct mount *mnt = real_mount(m);
	int err;

	if (m->mnt_sb == path->mnt->mnt_sb &&
	    m->mnt_root == path->dentry) {
		err = -ELOOP;
		goto fail;
	}

	err = do_add_mount(mnt, path, path->mnt->mnt_flags | MNT_SHRINKABLE, t);
	if (!err)
		return 0;
fail:
	if (!list_empty(&mnt->mnt_expire)) {
		namespace_lock();
		list_del_init(&mnt->mnt_expire);
		namespace_unlock();
	}
	mntput(m);
	mntput(m);
	return err;
}

static int my_follow_automount(struct path *path, unsigned flags, bool *need_mntput, struct task_struct *t)
{
	struct vfsmount *mnt;
	int err;

	if (!path->dentry->d_op || !path->dentry->d_op->d_automount)
		return -EREMOTE;

	if (!(flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY |
		     LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) &&
	    path->dentry->d_inode)
		return -EISDIR;

	t->total_link_count++;
	if (t->total_link_count >= 40)
		return -ELOOP;

	mnt = path->dentry->d_op->d_automount(path);
	if (IS_ERR(mnt)) {
		if (PTR_ERR(mnt) == -EISDIR && (flags & LOOKUP_PARENT))
			return -EREMOTE;
		return PTR_ERR(mnt);
	}

	if (!mnt) 
		return 0;

	if (!*need_mntput) {
		mntget(path->mnt);
		*need_mntput = true;
	}
	err = finish_automount(mnt, path);

	switch (err) {
	case -EBUSY:
		return 0;
	case 0:
		path_put(path);
		path->mnt = mnt;
		path->dentry = dget(mnt->mnt_root);
		return 0;
	default:
		return err;
	}

}
*/

int my_follow_managed(struct path *path, unsigned flags, struct task_struct *t)
{
	struct vfsmount *mnt = path->mnt; 
	unsigned managed;
	bool need_mntput = false;
	int ret = 0;

	while (managed = ACCESS_ONCE(path->dentry->d_flags),
	       managed &= DCACHE_MANAGED_DENTRY,
	       unlikely(managed != 0)) {
		if (managed & DCACHE_MANAGE_TRANSIT) {
			ret = path->dentry->d_op->d_manage(path->dentry, false);
			if (ret < 0)
				break;
		}

		/* Transit to a mounted filesystem. */
		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				need_mntput = true;
				continue;
			}
		/* we didn't consider this condition
		if (managed & DCACHE_NEED_AUTOMOUNT) {
			ret = my_follow_automount(path, flags, &need_mntput, t);
			if (ret < 0)
				break;
			continue;
		}
		*/
		}
		/* We didn't change the current path point */
		break;
	}

	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (ret == -EISDIR)
		ret = 0;
	return ret < 0 ? ret : need_mntput;
}


void path_put_conditional(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->path.mnt)
		mntput(path->mnt);
}

enum slow_d_compare {
	D_COMP_OK,
	D_COMP_NOMATCH,
	D_COMP_SEQRETRY,
};

struct hlist_bl_head *d_hash(const struct dentry *parent,
					unsigned int hash)
{
	hash += (unsigned long) parent / L1_CACHE_BYTES;
	hash = hash + (hash >> d_hash_shift);
	return dentry_hashtable + (hash & d_hash_mask);
}

unsigned long load_unaligned_zeropad(const void *addr)
{
	unsigned long ret, dummy;

	asm(
		"1:\tmov %2,%0\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:\t"
		"lea %2,%1\n\t"
		"and %3,%1\n\t"
		"mov (%1),%0\n\t"
		"leal %2,%%ecx\n\t"
		"andl %4,%%ecx\n\t"
		"shll $3,%%ecx\n\t"
		"shr %%cl,%0\n\t"
		"jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(1b, 3b)
		:"=&r" (ret),"=&c" (dummy)
		:"m" (*(unsigned long *)addr),
		 "i" (-sizeof(unsigned long)),
		 "i" (sizeof(unsigned long)-1));
	return ret;
}

int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount)
{
	unsigned long a,b,mask;

	for (;;) {
		a = *(unsigned long *)cs;
		b = load_unaligned_zeropad(ct);
		if (tcount < sizeof(unsigned long))
			break;
		if (unlikely(a != b))
			return 1;
		cs += sizeof(unsigned long);
		ct += sizeof(unsigned long);
		tcount -= sizeof(unsigned long);
		if (!tcount)
			return 0;
	}
	mask = bytemask_from_count(tcount);
	return unlikely(!!((a ^ b) & mask));
}

int dentry_cmp(const struct dentry *dentry, const unsigned char *ct, unsigned tcount)
{
	const unsigned char *cs;
	cs = ACCESS_ONCE(dentry->d_name.name);
	smp_read_barrier_depends();
	return dentry_string_cmp(cs, ct, tcount);
}


struct dentry *my__d_lookup(const struct dentry *parent, const struct qstr *name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct hlist_bl_head *b = d_hash(parent, hash);
	struct hlist_bl_node *node;
	struct dentry *found = NULL;
	struct dentry *dentry;

	rcu_read_lock();
	
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {

		if (dentry->d_name.hash != hash)
			continue;

		spin_lock(&dentry->d_lock);
		if (dentry->d_parent != parent)
			goto next;
		if (d_unhashed(dentry))
			goto next;

		/*
		 * It is safe to compare names since d_move() cannot
		 * change the qstr (protected by d_lock).
		 */
		if (parent->d_flags & DCACHE_OP_COMPARE) {
			int tlen = dentry->d_name.len;
			const char *tname = dentry->d_name.name;
			if (parent->d_op->d_compare(parent, dentry, tlen, tname, name))
				goto next;
		} else {
			if (dentry->d_name.len != len)
				goto next;
			if (dentry_cmp(dentry, str, len))
				goto next;
		}

		dentry->d_lockref.count++;
		found = dentry;
		spin_unlock(&dentry->d_lock);
		break;
next:
		spin_unlock(&dentry->d_lock);
 	}
 	rcu_read_unlock();

 	return found;
}

enum slow_d_compare slow_dentry_cmp(
		const struct dentry *parent,
		struct dentry *dentry,
		unsigned int seq,
		const struct qstr *name)
{
	int tlen = dentry->d_name.len;
	const char *tname = dentry->d_name.name;

	if (read_seqcount_retry(&dentry->d_seq, seq)) {
		cpu_relax();
		return D_COMP_SEQRETRY;
	}
	if (parent->d_op->d_compare(parent, dentry, tlen, tname, name))
		return D_COMP_NOMATCH;
	return D_COMP_OK;
}

struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name,
				unsigned *seqp)
{
	u64 hashlen = name->hash_len;
	const unsigned char *str = name->name;
	struct hlist_bl_head *b = d_hash(parent, hashlen_hash(hashlen));
	struct hlist_bl_node *node;
	struct dentry *dentry;
	hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
		unsigned seq;

seqretry:
		seq = raw_seqcount_begin(&dentry->d_seq);
		if (dentry->d_parent != parent)
			continue;
		if (d_unhashed(dentry))
			continue;

		if (unlikely(parent->d_flags & DCACHE_OP_COMPARE)) {
			if (dentry->d_name.hash != hashlen_hash(hashlen))
				continue;
			*seqp = seq;
			switch (slow_dentry_cmp(parent, dentry, seq, name)) {
			case D_COMP_OK:
				return dentry;
			case D_COMP_NOMATCH:
				continue;
			default:
				goto seqretry;
			}
		}

		if (dentry->d_name.hash_len != hashlen)
			continue;
		*seqp = seq;
		if (!dentry_cmp(dentry, str, hashlen_len(hashlen)))
			return dentry;
	}
	return NULL;
}

int my_lookup_fast(struct nameidata *nd, struct path *path, struct inode **inode, struct task_struct *t)
{
	struct vfsmount *mnt = nd->path.mnt;
	struct dentry *dentry, *parent = nd->path.dentry;
	int need_reval = 1;
	int status = 1;
	int err;

	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
		if (!dentry)
			goto unlazy;

		*inode = dentry->d_inode;
		if (read_seqcount_retry(&dentry->d_seq, seq))
			return -ECHILD;

		if (__read_seqcount_retry(&parent->d_seq, nd->seq))
			return -ECHILD;
		nd->seq = seq;

		if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE)) {
			status = dentry->d_op->d_revalidate(dentry, nd->flags);
			if (unlikely(status <= 0)) {
				if (status != -ECHILD)
					need_reval = 0;
				goto unlazy;
			}
		}
		path->mnt = mnt;
		path->dentry = dentry;
		if (unlikely(!__follow_mount_rcu(nd, path, inode)))
			goto unlazy;
		if (unlikely(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT))
			goto unlazy;
		return 0;
unlazy:
		if (my_unlazy_walk(nd, dentry, t))
			return -ECHILD;
	} else {
		dentry = my__d_lookup(parent, &nd->last);
	}

	if (unlikely(!dentry))
		goto need_lookup;

	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE) && need_reval)
		status = dentry->d_op->d_revalidate(dentry, nd->flags);
	if (unlikely(status <= 0)) {
		if (status < 0) {
			dput(dentry);
			return status;
		}
		if (!d_invalidate(dentry)) {
			dput(dentry);
			goto need_lookup;
		}
	}

	path->mnt = mnt;
	path->dentry = dentry;
	err = my_follow_managed(path, nd->flags, t);
	if (unlikely(err < 0)) {
		path_put_conditional(path, nd);
		return err;
	}
	if (err)
		nd->flags |= LOOKUP_JUMPED;
	*inode = path->dentry->d_inode;
	return 0;

need_lookup:
	return 1;
}

struct dentry *lookup_dcache(struct qstr *name, struct dentry *dir,unsigned int flags, bool *need_lookup)
{
	struct dentry *dentry;
	int error;

	*need_lookup = false;
	dentry = d_lookup(dir, name);
	if (dentry) {
		if (dentry->d_flags & DCACHE_OP_REVALIDATE) {
			error = dentry->d_op->d_revalidate(dentry, flags);
			if (unlikely(error <= 0)) {
				if (error < 0) {
					dput(dentry);
					return ERR_PTR(error);
				} else if (!d_invalidate(dentry)) {
					dput(dentry);
					dentry = NULL;
				}
			}
		}
	}

	if (!dentry) {
		dentry = d_alloc(dir, name);
		if (unlikely(!dentry))
			return ERR_PTR(-ENOMEM);

		*need_lookup = true;
	}
	return dentry;
}

struct dentry *lookup_real(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct dentry *old;

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir))) {
		dput(dentry);
		return ERR_PTR(-ENOENT);
	}

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

struct dentry *__lookup_hash(struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	bool need_lookup;
	struct dentry *dentry;

	dentry = lookup_dcache(name, base, flags, &need_lookup);
	if (!need_lookup)
		return dentry;

	return lookup_real(base->d_inode, dentry, flags);
}

int my_lookup_slow(struct nameidata *nd, struct path *path, struct task_struct *t)
{
	struct dentry *dentry, *parent;
	int err;

	parent = nd->path.dentry;
	BUG_ON(nd->inode != parent->d_inode);

	mutex_lock(&parent->d_inode->i_mutex);
	dentry = __lookup_hash(&nd->last, parent, nd->flags);
	mutex_unlock(&parent->d_inode->i_mutex);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	path->mnt = nd->path.mnt;
	path->dentry = dentry;
	err = my_follow_managed(path, nd->flags, t);
	if (unlikely(err < 0)) {
		path_put_conditional(path, nd);
		return err;
	}
	if (err)
		nd->flags |= LOOKUP_JUMPED;
	return 0;
}

int should_follow_link(struct dentry *dentry, int follow)
{
	return unlikely(d_is_symlink(dentry)) ? follow : 0;
}

void path_to_nameidata(const struct path *path,
					struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		dput(nd->path.dentry);
		if (nd->path.mnt != path->mnt)
			mntput(nd->path.mnt);
	}
	nd->path.mnt = path->mnt;
	nd->path.dentry = path->dentry;
}

void terminate_walk(struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		path_put(&nd->path);
	} else {
		nd->flags &= ~LOOKUP_RCU;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		rcu_read_unlock();
	}
}

int my_walk_component(struct nameidata *nd, struct path *path, int follow, struct task_struct *t)
{
	struct inode *inode;
	int err;

	if (unlikely(nd->last_type != LAST_NORM))
		return my_handle_dots(nd, nd->last_type, t);
	err = my_lookup_fast(nd, path, &inode, t);
	if (unlikely(err)) {
		if (err < 0)
			goto out_err;

		err = my_lookup_slow(nd, path, t);
		if (err < 0)
			goto out_err;

		inode = path->dentry->d_inode;
	}
	err = -ENOENT;
	if (!inode || d_is_negative(path->dentry))
		goto out_path_put;

	if (should_follow_link(path->dentry, follow)) {
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(nd->path.mnt != path->mnt ||
				     my_unlazy_walk(nd, path->dentry, t))) {
				err = -ECHILD;
				goto out_err;
			}
		}
		BUG_ON(inode != path->dentry->d_inode);
		return 1;
	}
	path_to_nameidata(path, nd);
	nd->inode = inode;
	return 0;

out_path_put:
	path_to_nameidata(path, nd);
out_err:
	terminate_walk(nd);
	return err;
}

/* should be continue! I have not finished it!
static inline int nested_symlink(struct path *path, struct nameidata *nd, struct task_struct *t)
{
	int res;

	if (unlikely(t->link_count >= MAX_NESTED_LINKS)) {
		path_put_conditional(path, nd);
		path_put(&nd->path);
		return -ELOOP;
	}
	BUG_ON(nd->depth >= MAX_NESTED_LINKS);

	nd->depth++;
	t->link_count++;

	do {
		struct path link = *path;
		void *cookie;

		res = follow_link(&link, nd, &cookie);
		if (res)
			break;
		res = walk_component(nd, path, LOOKUP_FOLLOW);
		put_link(nd, &link, cookie);
	} while (res > 0);

	current->link_count--;
	nd->depth--;
	return res;
}
*/

int my_link_path_walk(const char *name, struct nameidata *nd, struct task_struct *t)
{
	struct path next;
	int err;
	
	while (*name=='/')
		name++;
	if (!*name)
		return 0;

	/* At this point we know we have a real path component. */
	for(;;) {
		struct qstr this;
		long len;
		int type;

		err = my_may_lookup(nd, t);
 		if (err)
			break;

		len = my_hash_name(name, &this.hash);
		this.name = name;
		this.len = len;

		type = LAST_NORM;
		if (name[0] == '.') switch (len) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					break;
			}
		}

		nd->last = this;
		nd->last_type = type;

		if (!name[len])
			return 0;
		/*
		 * If it wasn't NUL, we know it was '/'. Skip that
		 * slash, and continue until no more slashes.
		 */
		do {
			len++;
		} while (unlikely(name[len] == '/'));
		if (!name[len])
			return 0;

		name += len;

		err = my_walk_component(nd, &next, LOOKUP_FOLLOW, t);
		if (err < 0)
			return err;

		/* should be continue, I have not finished it.
		if (err) {
			err = nested_symlink(&next, nd, t);
			if (err)
				return err;
		}
		*/
		if (!((nd->path.dentry->d_flags & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE)) {
			err = -ENOTDIR; 
			break;
		}
	}
	terminate_walk(nd);
	return err;
}

int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		nd->flags &= ~LOOKUP_RCU;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;

		if (!legitimize_mnt(nd->path.mnt, nd->m_seq)) {
			rcu_read_unlock();
			return -ECHILD;
		}
		if (unlikely(!lockref_get_not_dead(&dentry->d_lockref))) {
			rcu_read_unlock();
			mntput(nd->path.mnt);
			return -ECHILD;
		}
		if (read_seqcount_retry(&dentry->d_seq, nd->seq)) {
			rcu_read_unlock();
			dput(dentry);
			mntput(nd->path.mnt);
			return -ECHILD;
		}
		rcu_read_unlock();
	}

	if (likely(!(nd->flags & LOOKUP_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	path_put(&nd->path);
	return status;
}

int open_to_namei_flags(int flag)
{
	if ((flag & O_ACCMODE) == 3)
		flag--;
	return flag;
}

int my_current_umask(struct task_struct *t)
{
	return t->fs->umask;
}

bool my_inode_owner_or_capable(const struct inode *inode, struct task_struct *t)
{
	struct user_namespace *ns;

	if (uid_eq(my_current_fsuid(t), inode->i_uid))
		return true;

	ns = current_user_ns();
	if (my_ns_capable(ns, CAP_FOWNER, t) && kuid_has_mapping(ns, inode->i_uid))
		return true;
	return false;
}

int my_may_open(struct path *path, int acc_mode, int flag, struct task_struct *t)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	/* O_PATH? */
	if (!acc_mode) {
    DEBUG_LOG("next step is return 0!");
		return 0;
  }

	if (!inode) {
    DEBUG_LOG("next step is return -ENOENT!");
		return -ENOENT;
  }

	switch (inode->i_mode & S_IFMT) {
	case S_IFLNK:
    DEBUG_LOG("next step is return -ELOOP!");
		return -ELOOP;
	case S_IFDIR:
		if (acc_mode & MAY_WRITE) {
      DEBUG_LOG("next step is return -EISDIR!");
			return -EISDIR;
    }
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (path->mnt->mnt_flags & MNT_NODEV) {
      DEBUG_LOG("next step is return -EACCES!");
			return -EACCES;
    }
		/*FALLTHRU*/
	case S_IFIFO:
	case S_IFSOCK:
		flag &= ~O_TRUNC;
		break;
	}

	error = my_inode_permission(inode, acc_mode, t);
	if (error) {
    DEBUG_LOG("next step is return error!");
		return error;
  }

	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND)) {
      DEBUG_LOG("next step is return -EPERM!");
			return -EPERM;
    }
		if (flag & O_TRUNC) {
      DEBUG_LOG("next step is return -EPERM!");
			return -EPERM;
    }
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME && !my_inode_owner_or_capable(inode, t)) {
    DEBUG_LOG("next step is return -EPERM!");
		return -EPERM;
  }

  DEBUG_LOG("next step is return 0!");
	return 0;
}

void
locks_delete_global_locks(struct file_lock *fl)
{
	/*
	 * Avoid taking lock if already unhashed. This is safe since this check
	 * is done while holding the i_lock, and new insertions into the list
	 * also require that it be held.
	 */
	if (hlist_unhashed(&fl->fl_link))
		return;
	lg_local_lock_cpu(&file_lock_lglock, fl->fl_link_cpu);
	hlist_del_init(&fl->fl_link);
	lg_local_unlock_cpu(&file_lock_lglock, fl->fl_link_cpu);
}

void
locks_delete_global_blocked(struct file_lock *waiter)
{
	hash_del(&waiter->fl_link);
}

void __locks_delete_block(struct file_lock *waiter)
{
	locks_delete_global_blocked(waiter);
	list_del_init(&waiter->fl_block);
	waiter->fl_next = NULL;
}

void locks_wake_up_blocks(struct file_lock *blocker)
{
	/*
	 * Avoid taking global lock if list is empty. This is safe since new
	 * blocked requests are only added to the list under the i_lock, and
	 * the i_lock is always held here. Note that removal from the fl_block
	 * list does not require the i_lock, so we must recheck list_empty()
	 * after acquiring the blocked_lock_lock.
	 */
	if (list_empty(&blocker->fl_block))
		return;

	spin_lock(&blocked_lock_lock);
	while (!list_empty(&blocker->fl_block)) {
		struct file_lock *waiter;

		waiter = list_first_entry(&blocker->fl_block,
				struct file_lock, fl_block);
		__locks_delete_block(waiter);
		if (waiter->fl_lmops && waiter->fl_lmops->lm_notify)
			waiter->fl_lmops->lm_notify(waiter);
		else
			wake_up(&waiter->fl_wait);
	}
	spin_unlock(&blocked_lock_lock);
}

void locks_delete_lock(struct file_lock **thisfl_p)
{
	struct file_lock *fl = *thisfl_p;

	locks_delete_global_locks(fl);

	*thisfl_p = fl->fl_next;
	fl->fl_next = NULL;

	if (fl->fl_nspid) {
		put_pid(fl->fl_nspid);
		fl->fl_nspid = NULL;
	}

	locks_wake_up_blocks(fl);
	locks_free_lock(fl);
}

void my_locks_remove_flock(struct file *filp, struct task_struct *t)
{
	struct inode * inode = file_inode(filp);
	struct file_lock *fl;
	struct file_lock **before;

	if (!inode->i_flock)
		return;

	if (filp->f_op->flock) {
		struct file_lock fl = {
			.fl_pid = t->tgid,
			.fl_file = filp,
			.fl_flags = FL_FLOCK,
			.fl_type = F_UNLCK,
			.fl_end = OFFSET_MAX,
		};
		filp->f_op->flock(filp, F_SETLKW, &fl);
		if (fl.fl_ops && fl.fl_ops->fl_release_private)
			fl.fl_ops->fl_release_private(&fl);
	}

	spin_lock(&inode->i_lock);
	before = &inode->i_flock;

	while ((fl = *before) != NULL) {
		if (fl->fl_file == filp) {
			if (IS_FLOCK(fl)) {
				locks_delete_lock(before);
				continue;
			}
			if (IS_LEASE(fl)) {
				lease_modify(before, F_UNLCK);
				continue;
			}
			/* What? */
			BUG();
 		}
		before = &fl->fl_next;
	}
	spin_unlock(&inode->i_lock);
}

void drop_file_write_access(struct file *file)
{
	struct vfsmount *mnt = file->f_path.mnt;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;

	if (special_file(inode->i_mode))
		return;

	put_write_access(inode);
	if (file_check_writeable(file) != 0)
		return;
	__mnt_drop_write(mnt);
	file_release_write(file);
}

void file_free_rcu(struct rcu_head *head)
{
	struct file *f = container_of(head, struct file, f_u.fu_rcuhead);

	put_cred(f->f_cred);
	kmem_cache_free(filp_cachep, f);
}

int iint_initialized;

void file_free(struct file *f)
{
	percpu_counter_dec(&nr_files);
	file_check_state(f);
	call_rcu(&f->f_u.fu_rcuhead, file_free_rcu);
}

static struct rb_root integrity_iint_tree = RB_ROOT;
static DEFINE_RWLOCK(integrity_iint_lock);
static struct kmem_cache *iint_cache __read_mostly;

void my__fput(struct file *file, struct task_struct *t)
{
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = file->f_inode;

	might_sleep();

	fsnotify_close(file);

	//we didn't consider the implement of epoll, maybe we can do this next time
	//eventpoll_release(file);

	//should consider this again
	my_locks_remove_flock(file, t);

	if (unlikely(file->f_flags & FASYNC)) {
		if (file->f_op->fasync)
			file->f_op->fasync(-1, file, 0);
	}
	//should consider this again
	//ima_file_free(file);
	if (file->f_op->release)
		file->f_op->release(inode, file);
	//security_file_free(file);
	/* we didn't consider char_dev
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL &&
		     !(file->f_mode & FMODE_PATH))) {
		cdev_put(inode->i_cdev);
	}
	*/
	fops_put(file->f_op);
	put_pid(file->f_owner.pid);
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(inode);
	if (file->f_mode & FMODE_WRITE)
		drop_file_write_access(file);
	file->f_path.dentry = NULL;
	file->f_path.mnt = NULL;
	file->f_inode = NULL;
	file_free(file);
	dput(dentry);
	mntput(mnt);
}

void ____fput(struct callback_head *work, struct task_struct *t)
{
	my__fput(container_of(work, struct file, f_u.fu_rcuhead), t);
}

void delayed_fput(struct work_struct *unused, struct task_struct *t)
{
	struct llist_node *node = llist_del_all(&delayed_fput_list);
	struct llist_node *next;

	for (; node; node = next) {
		next = llist_next(node);
		my__fput(llist_entry(node, struct file, f_u.fu_llist), t);
	}
}

DECLARE_DELAYED_WORK(delayed_fput_work, delayed_fput);


static struct callback_head work_exited; 

void my_fput(struct file *file, struct task_struct *t)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		struct task_struct *task = t;

		if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			//we should consider this again
			//if (!task_work_add(task, &file->f_u.fu_rcuhead, true))
				//return;
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
		}

		if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
			schedule_delayed_work(&delayed_fput_work, 1);
	}
}

int my_atomic_open(struct nameidata *nd, struct dentry *dentry,
			struct path *path, struct file *file,
			const struct open_flags *op,
			bool got_write, bool need_lookup,
			int *opened, struct task_struct *t)
{
	struct inode *dir =  nd->path.dentry->d_inode;
	unsigned open_flag = open_to_namei_flags(op->open_flag);
	umode_t mode;
	int error;
	int acc_mode;
	int create_error = 0;
	struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
	bool excl;

	if (unlikely(IS_DEADDIR(dir))) {
		error = -ENOENT;
		goto out;
	}

	mode = op->mode;
	if ((open_flag & O_CREAT) && !IS_POSIXACL(dir))
		mode &= ~my_current_umask(t);

	excl = (open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT);
	if (excl)
		open_flag &= ~O_TRUNC;

	if (((open_flag & (O_CREAT | O_TRUNC)) ||
	    (open_flag & O_ACCMODE) != O_RDONLY) && unlikely(!got_write)) {
		if (!(open_flag & O_CREAT)) {
			goto no_open;
		} else if (open_flag & (O_EXCL | O_TRUNC)) {
			create_error = -EROFS;
			goto no_open;
		} else {
			create_error = -EROFS;
			open_flag &= ~O_CREAT;
		}
	}

	if (open_flag & O_CREAT) {
		error = my_inode_permission(&nd->path.dentry->d_inode, MAY_WRITE | MAY_EXEC, t);
		if (error) {
			create_error = error;
			if (open_flag & O_EXCL)
				goto no_open;
			open_flag &= ~O_CREAT;
		}
	}

	if (nd->flags & LOOKUP_DIRECTORY)
		open_flag |= O_DIRECTORY;

	file->f_path.dentry = DENTRY_NOT_SET;
	file->f_path.mnt = nd->path.mnt;
	error = dir->i_op->atomic_open(dir, dentry, file, open_flag, mode,
				      opened);
	if (error < 0) {
		if (create_error && error == -ENOENT)
			error = create_error;
		goto out;
	}

	if (error) {	/* returned 1, that is */
		if (WARN_ON(file->f_path.dentry == DENTRY_NOT_SET)) {
			error = -EIO;
			goto out;
		}
		if (file->f_path.dentry) {
			dput(dentry);
			dentry = file->f_path.dentry;
		}
		if (*opened & FILE_CREATED)
			fsnotify_create(dir, dentry);
		if (!dentry->d_inode) {
			WARN_ON(*opened & FILE_CREATED);
			if (create_error) {
				error = create_error;
				goto out;
			}
		} else {
			if (excl && !(*opened & FILE_CREATED)) {
				error = -EEXIST;
				goto out;
			}
		}
		goto looked_up;
	}

	acc_mode = op->acc_mode;
	if (*opened & FILE_CREATED) {
		WARN_ON(!(open_flag & O_CREAT));
		fsnotify_create(dir, dentry);
		acc_mode = MAY_OPEN;
	}
	error = my_may_open(&file->f_path, acc_mode, open_flag, t);
	if (error)
		my_fput(file, t);

out:
	dput(dentry);
	return error;

no_open:
	if (need_lookup) {
		dentry = lookup_real(dir, dentry, nd->flags);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);

		if (create_error) {
			int open_flag = op->open_flag;

			error = create_error;
			if ((open_flag & O_EXCL)) {
				if (!dentry->d_inode)
					goto out;
			} else if (!dentry->d_inode) {
				goto out;
			} else if ((open_flag & O_TRUNC) &&
				   S_ISREG(dentry->d_inode->i_mode)) {
				goto out;
			}
		}
	}
looked_up:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;
}

int my_may_create(struct inode *dir, struct dentry *child, struct task_struct *t)
{
	//audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return my_inode_permission(dir, MAY_WRITE | MAY_EXEC, t);
}

int my_vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool want_excl, struct task_struct *t)
{
	int error = my_may_create(dir, dentry, t);
	if (error)
		return error;

	if (!dir->i_op->create)
		return -EACCES;
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	//error = security_inode_create(dir, dentry, mode);
	//if (error)
	//	return error;
	error = dir->i_op->create(dir, dentry, mode, want_excl);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}

int my_lookup_open(struct nameidata *nd, struct path *path,
			struct file *file,
			const struct open_flags *op,
			bool got_write, int *opened, struct task_struct *t)
{
	struct dentry *dir = nd->path.dentry;
	struct inode *dir_inode = dir->d_inode;
	struct dentry *dentry;
	int error;
	bool need_lookup;

	*opened &= ~FILE_CREATED;
	dentry = lookup_dcache(&nd->last, dir, nd->flags, &need_lookup);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!need_lookup && dentry->d_inode)
		goto out_no_open;

	if ((nd->flags & LOOKUP_OPEN) && dir_inode->i_op->atomic_open) {
		return my_atomic_open(nd, dentry, path, file, op, got_write,
				   need_lookup, opened, t);
	}

	if (need_lookup) {
		BUG_ON(dentry->d_inode);

		dentry = lookup_real(dir_inode, dentry, nd->flags);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}

	/* Negative dentry, just create the file */
	if (!dentry->d_inode && (op->open_flag & O_CREAT)) {
		umode_t mode = op->mode;
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~my_current_umask(t);
		if (!got_write) {
			error = -EROFS;
			goto out_dput;
		}
		*opened |= FILE_CREATED;
		//error = security_path_mknod(&nd->path, dentry, mode, 0);
		//if (error)
		//	goto out_dput;
		error = my_vfs_create(dir->d_inode, dentry, mode,
				   nd->flags & LOOKUP_EXCL, t);
		if (error)
			goto out_dput;
	}
out_no_open:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;

out_dput:
	dput(dentry);
	return error;
}

int my_locks_mandatory_locked(struct inode *inode, struct task_struct *t)
{
	fl_owner_t owner = t->files;
	struct file_lock *fl;

	/*
	 * Search the lock list for this inode for any POSIX locks.
	 */
	spin_lock(&inode->i_lock);
	for (fl = inode->i_flock; fl != NULL; fl = fl->fl_next) {
		if (!IS_POSIX(fl))
			continue;
		if (fl->fl_owner != owner)
			break;
	}
	spin_unlock(&inode->i_lock);
	return fl ? -EAGAIN : 0;
}

int my_locks_verify_locked(struct inode *inode, struct task_struct *t)
{
	if (mandatory_lock(inode))
		return my_locks_mandatory_locked(inode, t);
	return 0;
}

int my_handle_truncate(struct file *filp, struct task_struct *t)
{
	struct path *path = &filp->f_path;
	struct inode *inode = path->dentry->d_inode;
	int error = get_write_access(inode);
	if (error)
		return error;
	/*
	 * Refuse to truncate files with mandatory locks held on them.
	 */
	error = my_locks_verify_locked(inode, t);
	//if (!error)
		//error = security_path_truncate(path);
	if (!error) {
		error = do_truncate(path->dentry, 0,
				    ATTR_MTIME|ATTR_CTIME|ATTR_OPEN,
				    filp);
	}
	put_write_access(inode);
	return error;
}

bool my_d_is_dir(const struct dentry *dentry)
{
	return ((dentry->d_flags & DCACHE_ENTRY_TYPE)== DCACHE_DIRECTORY_TYPE) || d_is_autodir(dentry);
}

bool my_d_can_lookup(const struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE;
}

int open_check_o_direct(struct file *f)
{
	/* NB: we're sure to have correct a_ops only after f_op->open */
	if (f->f_flags & O_DIRECT) {
		if (!f->f_mapping->a_ops ||
		    ((!f->f_mapping->a_ops->direct_IO) &&
		    (!f->f_mapping->a_ops->get_xip_mem))) {
			return -EINVAL;
		}
	}
	return 0;
}

int my_do_last(struct nameidata *nd, struct path *path,
		   struct file *file, const struct open_flags *op,
		   int *opened, struct filename *name, struct task_struct *t)
{
	struct dentry *dir = nd->path.dentry;
	int open_flag = op->open_flag;
	bool will_truncate = (open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int acc_mode = op->acc_mode;
	struct inode *inode;
	bool symlink_ok = false;
	struct path save_parent = { .dentry = NULL, .mnt = NULL };
	bool retried = false;
	int error;

	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= op->intent;

	if (nd->last_type != LAST_NORM) {
		error = my_handle_dots(nd, nd->last_type, t);
		if (error)
			return error;
    DEBUG_LOG("next step is goto finish_open!");
		goto finish_open;
	}

	if (!(open_flag & O_CREAT)) {
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		if (open_flag & O_PATH && !(nd->flags & LOOKUP_FOLLOW))
			symlink_ok = true;
		/* we _can_ be in RCU mode here */
		error = my_lookup_fast(nd, path, &inode, t);
		if (likely(!error)) {
      DEBUG_LOG("next step is goto finish_lookup!");
			goto finish_lookup;
    }

		if (error < 0) {
      DEBUG_LOG("next step is goto out!");
			goto out;
    }

		BUG_ON(nd->inode != dir->d_inode);
	} else {
		error = complete_walk(nd);
		if (error)
			return error;

		//audit_inode(name, dir, LOOKUP_PARENT);
		error = -EISDIR;
		/* trailing slashes? */
		if (nd->last.name[nd->last.len]) {
      DEBUG_LOG("next step is goto out!");
			goto out;
    }
	}

retry_lookup:
	if (op->open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
		error = mnt_want_write(nd->path.mnt);
		if (!error)
			got_write = true;
	}
	mutex_lock(&dir->d_inode->i_mutex);
	error = my_lookup_open(nd, path, file, op, got_write, opened, t);
	mutex_unlock(&dir->d_inode->i_mutex);

	if (error <= 0) {
		if (error) {
      DEBUG_LOG("next step is goto out!");
			goto out;
    }

		if ((*opened & FILE_CREATED) ||
		    !S_ISREG(file_inode(file)->i_mode))
			will_truncate = false;

		//audit_inode(name, file->f_path.dentry, 0);
    DEBUG_LOG("next step is goto opened!");
		goto opened;
	}

	if (*opened & FILE_CREATED) {
		/* Don't check for write permission, don't truncate */
		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = MAY_OPEN;
		path_to_nameidata(path, nd);
    DEBUG_LOG("next step is goto finish_open_created!");
		goto finish_open_created;
	}

	/*
	 * create/update audit record if it already exists.
	 */
	//if (d_is_positive(path->dentry))
		//audit_inode(name, path->dentry, 0);

	/*
	 * If atomic_open() acquired write access it is dropped now due to
	 * possible mount and symlink following (this might be optimized away if
	 * necessary...)
	 */
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}

	error = -EEXIST;
	if ((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT)) {
    DEBUG_LOG("next step is goto exit_dput!");
		goto exit_dput;
  }

	error = my_follow_managed(path, nd->flags, t);
	if (error < 0) {
    DEBUG_LOG("next step is goto exit_dput!");
		goto exit_dput;
  }

	if (error)
		nd->flags |= LOOKUP_JUMPED;

	BUG_ON(nd->flags & LOOKUP_RCU);
	inode = path->dentry->d_inode;
finish_lookup:
	/* we _can_ be in RCU mode here */
	error = -ENOENT;
	if (!inode || d_is_negative(path->dentry)) {
		path_to_nameidata(path, nd);
    DEBUG_LOG("next step is goto out!");
		goto out;
	}

	/*
	if (should_follow_link(path->dentry, !symlink_ok)) {
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(nd->path.mnt != path->mnt ||
				     unlazy_walk(nd, path->dentry))) {
				error = -ECHILD;
				goto out;
			}
		}
		BUG_ON(inode != path->dentry->d_inode);
		return 1;
	}
	*/

	if ((nd->flags & LOOKUP_RCU) || nd->path.mnt != path->mnt) {
		path_to_nameidata(path, nd);
	} else {
		save_parent.dentry = nd->path.dentry;
		save_parent.mnt = mntget(path->mnt);
		nd->path.dentry = path->dentry;

	}
	nd->inode = inode;
	/* Why this, you ask?  _Now_ we might have grown LOOKUP_JUMPED... */
finish_open:
	error = complete_walk(nd);
	if (error) {
		path_put(&save_parent);
		return error;
	}
	//audit_inode(name, nd->path.dentry, 0);
	error = -EISDIR;
	if ((open_flag & O_CREAT) && my_d_is_dir(nd->path.dentry)) {
    DEBUG_LOG("next step is goto out!");
		goto out;
  }
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !my_d_can_lookup(nd->path.dentry)) {
    DEBUG_LOG("next step is goto out!");
		goto out;
  }
	if (!S_ISREG(nd->inode->i_mode))
		will_truncate = false;

	if (will_truncate) {
		error = mnt_want_write(nd->path.mnt);
		if (error) {
      DEBUG_LOG("next step is goto out!");
			goto out;
    }
		got_write = true;
	}
finish_open_created:
	error = my_may_open(&nd->path, acc_mode, open_flag, t);
	if (error) {
    DEBUG_LOG("next step is goto out!");
		goto out;
  }

	BUG_ON(*opened & FILE_OPENED); /* once it's opened, it's opened */
	printk(KERN_INFO "before vfs_open, current->files is %p, error number is %d\n", t->files, error);
	//error = vfs_open(&nd->path, file, my_current_cred(t));
	printk(KERN_INFO "after vfs_open,current->files is %p, error number is %d\n", t->files, error);
	if (!error) {
		*opened |= FILE_OPENED;
	} else {
		if (error == -EOPENSTALE) {
      DEBUG_LOG("next step is stale_open!");
			goto stale_open;
    }
    DEBUG_LOG("next step is out!");
		goto out;
	}
opened:
	error = open_check_o_direct(file);
	if (error) {
    DEBUG_LOG("next step is exit_fout!");
		goto exit_fput;
  }
	error = ima_file_check(file, op->acc_mode);
	if (error) {
    DEBUG_LOG("next step is exit_fout!");
		goto exit_fput;
  }
	if (will_truncate) {
		error = my_handle_truncate(file, t);
		printk(KERN_INFO "my_handle_truncate execed ! current->files is %p\n", t->files);
		if (error) {
      DEBUG_LOG("next step is exit_fout!");
			goto exit_fput;
    }
	}
out:
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	path_put(&save_parent);
	terminate_walk(nd);
	return error;

exit_dput:
	path_put_conditional(path, nd);
  DEBUG_LOG("next step is out!");
	goto out;
exit_fput:
	fput(file);
  DEBUG_LOG("next step is out!");
	goto out;

stale_open:
	if (!save_parent.dentry || retried) {
    DEBUG_LOG("next step is out!");
		goto out;
  }

	BUG_ON(save_parent.dentry != dir);
	path_put(&nd->path);
	nd->path = save_parent;
	nd->inode = dir->d_inode;
	save_parent.mnt = NULL;
	save_parent.dentry = NULL;
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}
	retried = true;
  DEBUG_LOG("next step is retry_lookup!");
	goto retry_lookup;
}

void put_filp(struct file *file)
{
	if (atomic_long_dec_and_test(&file->f_count)) {
		//security_file_free(file);
		file_free(file);
	}
}

struct file *my_path_openat(int dfd, struct filename *pathname, struct nameidata *nd, const struct open_flags *op, int flags, struct task_struct *t)
{
	struct file *base = NULL;
	struct file *file;
	struct path path;
	int opened = 0;
	int error;

	DEBUG_LOG("enter my_get_empty_filp!");
	file = my_get_empty_filp(t);
	printk(KERN_ALERT "current->files is %p\n", t->files);
	if (IS_ERR(file))
		return file;

	file->f_flags = op->open_flag;

	/* we didn't consider tmpfile
	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(dfd, pathname, nd, flags, op, file, &opened, t);
		goto out;
	}
	*/

	DEBUG_LOG("enter path_init!");
	error = path_init(dfd, pathname->name, flags | LOOKUP_PARENT, nd, &base, t);
	printk(KERN_ALERT "current->files is %p\n", t->files);
	if (unlikely(error))
		goto out;

	t->total_link_count = 0;

  DEBUG_LOG("enter my_link_path_walk!");
	error = my_link_path_walk(pathname->name, nd, t);
	printk(KERN_ALERT "current->files is %p\n", t->files);
	if (unlikely(error))
		goto out;

	DEBUG_LOG("enter my_do_last!");
	error = my_do_last(nd, &path, file, op, &opened, pathname, t);
	printk(KERN_ALERT "current->files is %p\n", t->files);
	/* we didn't consider symlink
	while (unlikely(error > 0)) 
		struct path link = path;
		void *cookie;
		if (!(nd->flags & LOOKUP_FOLLOW)) {
			path_put_conditional(&path, nd);
			path_put(&nd->path);
			error = -ELOOP;
			break;
		}
		error = may_follow_link(&link, nd);
		if (unlikely(error))
			break;
		nd->flags |= LOOKUP_PARENT;
		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
		error = follow_link(&link, nd, &cookie);
		if (unlikely(error))
			break;
		error = do_last(nd, &path, file, op, &opened, pathname);
		put_link(nd, &link, cookie);
	}
	*/
out:
	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT))
		path_put(&nd->root);
	if (base)
		my_fput(base, t);
	if (!(opened & FILE_OPENED)) {
		BUG_ON(!error);
		put_filp(file);
	}
	if (unlikely(error)) {
		if (error == -EOPENSTALE) {
			if (flags & LOOKUP_RCU)
				error = -ECHILD;
			else
				error = -ESTALE;
		}
		file = ERR_PTR(error);
	}
	return file;
}

struct file *my_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op, struct task_struct *t) 
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	DEBUG_LOG("enter my_path_openat!");
	filp = my_path_openat(dfd, pathname, &nd, op, flags | LOOKUP_RCU, t);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = my_path_openat(dfd, pathname, &nd, op, flags, t);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = my_path_openat(dfd, pathname, &nd, op, flags | LOOKUP_REVAL, t);
	return filp;
}


