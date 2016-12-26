#include "ext4_open.h"

static __cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_list_lock);
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_state_lock);
__cacheline_aligned_in_smp DEFINE_SPINLOCK(dq_data_lock);
// EXPORT_SYMBOL(dq_data_lock);

static LIST_HEAD(inuse_list);
static LIST_HEAD(free_dquots);
static unsigned int dq_hash_bits, dq_hash_mask;
static struct hlist_head *dquot_hash;

/* ------------------------ ext4 文件系统的数据和结构 ----------------- */
/*
void __ext4_msg(struct super_block *sb,
                const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!___ratelimit(&(EXT4_SB(sb)->s_msg_ratelimit_state), "EXT4-fs"))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sEXT4-fs (%s): %pV\n", prefix, sb->s_id, &vaf);
	va_end(args);
}

const char *ext4_decode_error(struct super_block *sb, int errno,
                              char nbuf[16])
{
	char *errstr = NULL;

	switch (errno) {
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		if (!sb || (EXT4_SB(sb)->s_journal &&
                EXT4_SB(sb)->s_journal->j_flags & JBD2_ABORT))
			errstr = "Journal has aborted";
		else
			errstr = "Readonly filesystem";
		break;
	default:
    if (nbuf) {
			if (snprintf(nbuf, 16, "error %d", -errno) >= 0)
				errstr = nbuf;
		}
		break;
	}

	return errstr;
}


void ext4_journal_abort_handle(const char *caller, unsigned int line,
                               const char *err_fn, struct buffer_head *bh,
                               handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = ext4_decode_error(NULL, err, nbuf);
	BUG_ON(!ext4_handle_valid(handle));
	if (bh)
		BUFFER_TRACE(bh, "abort");
	if (!handle->h_err)
		handle->h_err = err;
	if (is_handle_aborted(handle))
		return;
	printk(KERN_ERR "EXT4-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);
	jbd2_journal_abort_handle(handle);
}

static __le32 ext4_superblock_csum(struct super_block *sb,
                                   struct ext4_super_block *es)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int offset = offsetof(struct ext4_super_block, s_checksum);
	__u32 csum;
	csum = ext4_chksum(sbi, ~0, (char *)es, offset);
	return cpu_to_le32(csum);
}

void ext4_superblock_csum_set(struct super_block *sb)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	if (!ext4_has_metadata_csum(sb))
		return;
	es->s_checksum = ext4_superblock_csum(sb, es);
}

static void __save_error_info(struct super_block *sb, const char *func,
                              unsigned int line)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	EXT4_SB(sb)->s_mount_state |= EXT4_ERROR_FS;
	es->s_state |= cpu_to_le16(EXT4_ERROR_FS);
	es->s_last_error_time = cpu_to_le32(get_seconds());
	strncpy(es->s_last_error_func, func, sizeof(es->s_last_error_func));
	es->s_last_error_line = cpu_to_le32(line);
	if (!es->s_first_error_time) {
		es->s_first_error_time = es->s_last_error_time;
		strncpy(es->s_first_error_func, func,
            sizeof(es->s_first_error_func));
		es->s_first_error_line = cpu_to_le32(line);
		es->s_first_error_ino = es->s_last_error_ino;
		es->s_first_error_block = es->s_last_error_block;
	}
	if (!es->s_error_count)
		mod_timer(&EXT4_SB(sb)->s_err_report, jiffies + 24*60*60*HZ);
	le32_add_cpu(&es->s_error_count, 1);
}

static int block_device_ejected(struct super_block *sb)
{
	struct inode *bd_inode = sb->s_bdev->bd_inode;
	struct backing_dev_info *bdi = bd_inode->i_mapping->backing_dev_info;

	return bdi->dev == NULL;
}

static int ext4_commit_super(struct super_block *sb, int sync)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	struct buffer_head *sbh = EXT4_SB(sb)->s_sbh;
	int error = 0;

	if (!sbh || block_device_ejected(sb))
		return error;
	if (buffer_write_io_error(sbh)) {
		ext4_msg(sb, KERN_ERR, "previous I/O error to "
		       "superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	if (!(sb->s_flags & MS_RDONLY))
		es->s_wtime = cpu_to_le32(get_seconds());
	if (sb->s_bdev->bd_part)
		es->s_kbytes_written =
			cpu_to_le64(EXT4_SB(sb)->s_kbytes_written +
			    ((part_stat_read(sb->s_bdev->bd_part, sectors[1]) -
			      EXT4_SB(sb)->s_sectors_written_start) >> 1));
	else
		es->s_kbytes_written =
			cpu_to_le64(EXT4_SB(sb)->s_kbytes_written);
	ext4_free_blocks_count_set(es,
			EXT4_C2B(EXT4_SB(sb), percpu_counter_sum_positive(
				&EXT4_SB(sb)->s_freeclusters_counter)));
	es->s_free_inodes_count =
		cpu_to_le32(percpu_counter_sum_positive(
				&EXT4_SB(sb)->s_freeinodes_counter));
	BUFFER_TRACE(sbh, "marking dirty");
	ext4_superblock_csum_set(sb);
	mark_buffer_dirty(sbh);
	if (sync) {
		error = sync_dirty_buffer(sbh);
		if (error)
			return error;
		error = buffer_write_io_error(sbh);
		if (error) {
			ext4_msg(sb, KERN_ERR, "I/O error while writing "
			       "superblock");
			clear_buffer_write_io_error(sbh);
			set_buffer_uptodate(sbh);
		}
	}
	return error;
}

static void save_error_info(struct super_block *sb, const char *func,
                            unsigned int line)
{
	__save_error_info(sb, func, line);
	ext4_commit_super(sb, 1);
}

void __ext4_abort(struct super_block *sb, const char *function,
                  unsigned int line, const char *fmt, ...)
{
	va_list args;

	save_error_info(sb, function, line);
	va_start(args, fmt);
	printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: ", sb->s_id,
	       function, line);
	vprintk(fmt, args);
	printk("\n");
	va_end(args);

	if ((sb->s_flags & MS_RDONLY) == 0) {
		ext4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		EXT4_SB(sb)->s_mount_flags |= EXT4_MF_FS_ABORTED;
		smp_wmb();
		sb->s_flags |= MS_RDONLY;
		if (EXT4_SB(sb)->s_journal)
			jbd2_journal_abort(EXT4_SB(sb)->s_journal, -EIO);
		save_error_info(sb, function, line);
	}
	if (test_opt(sb, ERRORS_PANIC)) {
		if (EXT4_SB(sb)->s_journal &&
        !(EXT4_SB(sb)->s_journal->j_flags & JBD2_REC_ERR))
			return;
		panic("EXT4-fs panic from previous error\n");
	}
}

static void ext4_handle_error(struct super_block *sb)
{
	if (sb->s_flags & MS_RDONLY)
		return;

	if (!test_opt(sb, ERRORS_CONT)) {
		journal_t *journal = EXT4_SB(sb)->s_journal;

		EXT4_SB(sb)->s_mount_flags |= EXT4_MF_FS_ABORTED;
		if (journal)
			jbd2_journal_abort(journal, -EIO);
	}
	if (test_opt(sb, ERRORS_RO)) {
		ext4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		smp_wmb();
		sb->s_flags |= MS_RDONLY;
	}
	if (test_opt(sb, ERRORS_PANIC)) {
		if (EXT4_SB(sb)->s_journal &&
        !(EXT4_SB(sb)->s_journal->j_flags & JBD2_REC_ERR))
			return;
		panic("EXT4-fs (device %s): panic forced after error\n",
          sb->s_id);
	}
}

void __ext4_std_error(struct super_block *sb, const char *function,
                      unsigned int line, int errno)
{
	char nbuf[16];
	const char *errstr;
	if (errno == -EROFS && journal_current_handle() == NULL &&
	    (sb->s_flags & MS_RDONLY))
		return;

	if (ext4_error_ratelimit(sb)) {
		errstr = ext4_decode_error(sb, errno, nbuf);
		printk(KERN_CRIT "EXT4-fs error (device %s) in %s:%d: %s\n",
		       sb->s_id, function, line, errstr);
	}

	save_error_info(sb, function, line);
	ext4_handle_error(sb);
}


static void ext4_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

static int ext4_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();
	if (sb->s_flags & MS_RDONLY)
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = EXT4_SB(sb)->s_journal;
	if (journal && is_journal_aborted(journal)) {
		ext4_abort(sb, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

static handle_t *ext4_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= EXT4_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}

int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!ext4_handle_valid(handle)) {
		ext4_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = jbd2_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = jbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__ext4_std_error(sb, where, line, err);
	return err;
}

int __ext4_journal_get_write_access(const char *where, unsigned int line,
                                    handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_get_write_access(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__, bh,
                                handle, err);
	}
	return err;
}

int __ext4_handle_dirty_super(const char *where, unsigned int line,
                              handle_t *handle, struct super_block *sb)
{
	struct buffer_head *bh = EXT4_SB(sb)->s_sbh;
	int err = 0;

	ext4_superblock_csum_set(sb);
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__,
                                bh, handle, err);
	} else
		mark_buffer_dirty(bh);
	return err;
}

handle_t *__ext4_journal_start_sb(struct super_block *sb, unsigned int line,
                                  int type, int blocks, int rsv_blocks)
{
	journal_t *journal;
	int err;

	trace_ext4_journal_start(sb, blocks, rsv_blocks, _RET_IP_);
	err = ext4_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = EXT4_SB(sb)->s_journal;
	if (!journal)
		return ext4_get_nojournal();
	return jbd2__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
                             type, line);
}
*/

int ext4_inode_attach_jinode(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct jbd2_inode *jinode;

	if (ei->jinode || !EXT4_SB(inode->i_sb)->s_journal)
		return 0;

	jinode = jbd2_alloc_inode(GFP_KERNEL);
	spin_lock(&inode->i_lock);
	if (!ei->jinode) {
		if (!jinode) {
			spin_unlock(&inode->i_lock);
			return -ENOMEM;
		}
		ei->jinode = jinode;
		jbd2_journal_init_jbd_inode(ei->jinode, inode);
		jinode = NULL;
	}
	spin_unlock(&inode->i_lock);
	if (unlikely(jinode != NULL))
		jbd2_free_inode(jinode);
	return 0;
}

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
// EXPORT_SYMBOL(dqget);


int my_ext4_file_open(struct inode * inode, struct file * filp, struct task_struct *t)
{
  DEBUG_LOG("entry my_ext4_file_open()!");
	struct super_block *sb = inode->i_sb;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct vfsmount *mnt = filp->f_path.mnt;
	struct path path;
	char buf[64], *cp;
  printk("FILE = %s, LINE = %d, FUNC = %s, current = %p, current->files = %p\n", __FILE__, __LINE__, __FUNCTION__, t, t->files);

	if (unlikely(!(sbi->s_mount_flags & EXT4_MF_MNTDIR_SAMPLED) && !(sb->s_flags & MS_RDONLY))) {
		sbi->s_mount_flags |= EXT4_MF_MNTDIR_SAMPLED;
		/*
		 * Sample where the filesystem has been mounted and
		 * store it in the superblock for sysadmin convenience
		 * when trying to sort through large numbers of block
		 * devices or filesystem images.
		 */
    printk("FILE = %s, LINE = %d, FUNC = %s, current = %p, current->files = %p\n", __FILE__, __LINE__, __FUNCTION__, t, t->files);
		memset(buf, 0, sizeof(buf));
		path.mnt = mnt;
		path.dentry = mnt->mnt_root;
		cp = d_path(&path, buf, sizeof(buf));
    /*
		if (!IS_ERR(cp)) {
			handle_t *handle;
			int err;

			handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
			if (IS_ERR(handle))
				return PTR_ERR(handle);
			err = ext4_journal_get_write_access(handle, sbi->s_sbh);
			if (err) {
				ext4_journal_stop(handle);
				return err;
			}
			strlcpy(sbi->s_es->s_last_mounted, cp, sizeof(sbi->s_es->s_last_mounted));
			ext4_handle_dirty_super(handle, sb);
			ext4_journal_stop(handle);
		}
    */
	}
  printk("FILE = %s, LINE = %d, FUNC = %s, current = %p, current->files = %p\n", __FILE__, __LINE__, __FUNCTION__, t, t->files);
	/*
	 * Set up the jbd2_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		int ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}
  printk("FILE = %s, LINE = %d, FUNC = %s, current = %p, current->files = %p\n", __FILE__, __LINE__, __FUNCTION__, t, t->files);
	return dquot_file_open(inode, filp);
}


